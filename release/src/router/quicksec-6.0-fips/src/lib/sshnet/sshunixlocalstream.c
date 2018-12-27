/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of local streams for Unix.
*/

#include "sshincludes.h"

#ifdef HAVE_SYS_UN_H

#include "sshlocalstream.h"
#include "ssheloop.h"
#include "sshfdstream.h"

#include <sys/socket.h>
#include <sys/un.h>

#define SSH_DEBUG_MODULE "SshUnixLocalStream"

struct SshLocalListenerRec {
  SshIOHandle sock;
  char *path;
  SshLocalCallback callback;
  void *context;
};


/* This callback is called whenever a new connection is made to a listener
   socket. */

void ssh_local_listen_callback(unsigned int events, void *context)
{
  SshLocalListener listener = (SshLocalListener)context;
  SshIOHandle sock;
  struct sockaddr_un sunaddr;
  SshStream str;
  ssh_socklen_t addrlen;

  if (events & SSH_IO_READ)
    {
      addrlen = sizeof(sunaddr);
      sock = accept(listener->sock, (struct sockaddr *)&sunaddr, &addrlen);
      if (sock < 0)
        {
          ssh_debug("ssh_local_listen_callback: accept failed");
          return;
        }

      /* Re-enable requests on the listener. */
      ssh_io_set_fd_request(listener->sock, SSH_IO_READ);

      str = ssh_stream_fd_wrap(sock, TRUE);

      if (str == NULL)
        {
          close(sock);
          ssh_warning("insufficient resources to accept new connection");
          return;
        }

      /* Inform user callback of the new socket.  Note that this might
         destroy the listener. */
      (*listener->callback)(str, listener->context);
    }
}

/* Creates a local listener for receiving connections to the supplied
   path.  If there already is a listener for the specified path, this
   fails.  Otherwise, this reserves the given pathname, and any
   connect requests with the same path will result in a call to the
   supplied callback.  The listener created by this is only accessible
   from within the local machine.  The implementation must provide the
   necessary access control mechanisms to guarantee that connections
   cannot be made from outside the local machine. */

SshLocalListener ssh_local_make_listener(const unsigned char *path,
                                         SshLocalStreamParams params,
                                         SshLocalCallback callback,
                                         void *context)
{
  SshIOHandle sock;
  struct sockaddr_un sunaddr;
  SshLocalListener listener;





  if (strlen(ssh_csstr(path)) >= (sizeof(sunaddr.sun_path) - 1))
    {
      ssh_warning("Can not create local domain socket: Path too long");
      return NULL;
    }

  /* Create a socket for the listener. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      ssh_warning("Can not create local domain socket: %.200s",
                  strerror(errno));
      return NULL;
    }

  /* Initialize a unix-domain address structure. */
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, ssh_csstr(path), sizeof(sunaddr.sun_path) - 1);

  /* Bind the socket to the address.  This will create the socket in the file
     system, and will fail if the socket already exists. */
  if (bind(sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr)) < 0)
    {
      close(sock);
      ssh_warning("Can not bind local address %.200s: %.200s",
                  path, strerror(errno));
      return NULL;
    }

  /* Start listening for connections to the socket. */
  if (listen(sock, 5) < 0)
    {
      close(sock);
      ssh_warning("Can not listen to local address %.200s: %.200s",
                  path, strerror(errno));
      return NULL;
    }

  /* Allocate and initialize the listener structure. */
  listener = ssh_malloc(sizeof(*listener));

  if (listener == NULL)
    {
      close(sock);
      ssh_warning("Could not allocate memory for listener socket state");
      return NULL;
    }

  listener->sock = sock;
  listener->path = ssh_strdup(path);

  if (listener->path == NULL)
    {
      close(sock);
      ssh_free(listener);
      ssh_warning("Could not allocate memory for listener socket state");
      return NULL;
    }

  listener->callback = callback;
  listener->context = context;

  /* ssh_local_listen_callback will call the user supplied callback
     when after new connection is accepted. It also creates stream
     object for the new connection and calls callback. */
  if (ssh_io_register_fd(sock, ssh_local_listen_callback, (void *)listener)
      == FALSE)
    {
      close(sock);
      ssh_free(listener->path);
      ssh_free(listener);
      ssh_warning("Failed to register file descriptor: Out of memory");
      return NULL;
    }
  ssh_io_set_fd_request(sock, SSH_IO_READ);

  return listener;
}

/* Context structure for connecting to the listener. */

typedef struct SshLocalConnectRec
{
  SshIOHandle sock;
  char *path;
  SshLocalCallback callback;
  void *context;
  Boolean aborted;
  SshOperationHandle op;
} *SshLocalConnect;

/* This is called if somebody aborts the asynchrnous local connect */
void ssh_local_connect_abort(void *context)
{
  SshLocalConnect c = context;
  c->aborted = TRUE;
}

/* This function is called whenever something happens with our
   asynchronous connect attempt. This is also used for the starting
   the operation initially. */
SshOperationHandle ssh_local_connect_try(unsigned int events, void *context)
{
  SshLocalConnect c = (SshLocalConnect)context;
  int ret;
  struct sockaddr_un sunaddr;
  SshStream str;

  if (c->aborted)
    {
      /* The local connect was aborted */
      ssh_io_unregister_fd(c->sock, FALSE);
      close(c->sock);
      ssh_free(c->path);
      ssh_free(c);
      return NULL;
    }

  /* Initialize the address to connect to. */
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy(sunaddr.sun_path, c->path, sizeof(sunaddr.sun_path) - 1);

  /* Make a non-blocking connect attempt. */
  ret = connect(c->sock, (struct sockaddr *)&sunaddr, AF_UNIX_SIZE(sunaddr));
  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      /* Successful connection. */
      ssh_io_unregister_fd(c->sock, FALSE);
      str = ssh_stream_fd_wrap(c->sock, TRUE);

      if (str == NULL)
        {
          close(c->sock);
          c->sock = -1;
          SSH_DEBUG(SSH_D_FAIL,
                    ("Insufficient memory to create TCP stream."));
          (*c->callback)(NULL,c->context);
          ssh_free(c->path);
          ssh_free(c);
          return NULL;
        }

      (*c->callback)(str, c->context);
      if (c->op)
        ssh_operation_unregister(c->op);
      ssh_free(c->path);
      ssh_free(c);
      return NULL;
    }
  if (errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EALREADY)
    {
      /* Connection still in progress.  */
      ssh_io_set_fd_request(c->sock, SSH_IO_WRITE);
      if (c->op == NULL)
        {
          /* Asynchronous connect. Create an operation handle which
             can be used to cancel the connect */
          c->op = ssh_operation_register(ssh_local_connect_abort, c);
        }
      return c->op;
    }

  /* Connection failed. */
  ssh_io_unregister_fd(c->sock, FALSE);
  close(c->sock);
  (*c->callback)(NULL, c->context);
  ssh_free(c->path);
  ssh_free(c);
  return NULL;
}

/* This function is called whenever something happens with our asynchronous
   connect attempt.  */
void ssh_local_connect_try_cb(unsigned int events, void *context)
{
  /* Make a call to the real worker */
  ssh_local_connect_try(events, context);
}


/* Destroys the local listener.  However, this might leave entries in
   the file system on some systems.  (For example, in Unix this does
   not remove the unix-domain socket, as this might be called after a
   fork, and we might wish to continue receiving connections in the
   other fork.)  Thus, it is recommended that remove() be called for
   the path to ensure that any garbage has been removed.  (The remove
   call should probably be made just before creating a new listener,
   in case the application has previously crashed before destroying
   the listener). */

void ssh_local_destroy_listener(SshLocalListener listener)
{
  ssh_io_unregister_fd(listener->sock, FALSE);
  close(listener->sock);
  ssh_free(listener->path);
  ssh_free(listener);
}
/* Connects to the local listener with the given path.  The callback
   will be colled when the connection is complete or has failed. If
   the connection is successful, an SshStream object is created and
   passed to the callback.  If connecting fails, NULL is passed to the
   callback as the stream. */

SshOperationHandle ssh_local_connect(const unsigned char *path,
                                     SshLocalCallback callback,
                                     void *context)
{
  SshIOHandle sock;
  SshLocalConnect c;

  c = NULL;

  /* Create a unix-domain socket. */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    goto fail;

  /* Allocate and initialize a context structure. */
  c = ssh_calloc(1, sizeof(*c));

  if (c == NULL)
    goto fail;

  c->path = ssh_strdup(path);

  if (c->path == NULL)
    goto fail;

  c->sock = sock;
  c->callback = callback;
  c->context = context;

  /* Register the file descriptor.  Note that this also makes it
     non-blocking. */
  if (ssh_io_register_fd(sock, ssh_local_connect_try_cb, c)
      == FALSE)
    goto fail;

  /* Fake a callback to start asynchronous connect. This connect could be
     done on this current routine, but we want this to be similar with
     tcp/ip socket code, so we use the try-routines */
  return ssh_local_connect_try(SSH_IO_WRITE, (void *)c);

 fail:

  if (sock != -1)
    close(sock);

  if (c != NULL)
    {
      if (c->path != NULL)
        ssh_free(c->path);

      ssh_free(c);
    }

  (*callback)(NULL,context);
  return NULL;
}

#endif /* HAVE_SYS_UN_H */
