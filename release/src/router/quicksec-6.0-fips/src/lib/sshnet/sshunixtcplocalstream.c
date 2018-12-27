/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of local streams for Windows.
   This implementation is generic for any operating
   system with ssh_tcp implemented.
*/

#include "sshincludes.h"

#ifndef HAVE_SYS_UN_H

#include "sshlocalstream.h"
#include "sshtcp.h"
#include "sshrand.h"

struct SshLocalListenerRec {
  int sock;
  char *path;
  SshTcpListener tcplistener;
  SshLocalCallback callback;
  void *context;
};

/* Someone has opened a connection to the TCP port and TCP library
   calls us.  We now call the original local listener callback. */
static void ssh_local_listen_callback(SshTcpError error,
                                      SshStream stream,
                                      void *context)
{
  SshLocalListener listener = (SshLocalListener)context;

  if (error == SSH_TCP_NEW_CONNECTION) {
    (listener->callback)(stream, listener->context);
  } else {
    if (stream)
      ssh_stream_destroy(stream);
  }
  return;
}

/* Creates a local listener for receiving connections to the supplied
   path.  If there already is a listener for the specified path, this
   fails.  Otherwise, this reserves the given pathname, and any
   connect requests with the same path will result in a call to the
   supplied callback.  The listener created by this is only accessible
   from within the local machine.  The implementation must provide the
   necessary access control mechanisms to guarantee that connections
   cannot be made from outside the local machine. */

#define _LOCAL_PORT_MIN         25678
#define _LOCAL_PORT_MAX         56789
#define _LOCAL_RETRY_MAX        128

SshLocalListener ssh_local_make_listener(const unsigned char *path,
                                         SshLocalStreamParams params,
                                         SshLocalCallback callback,
                                         void *context)
{
  SshLocalListener listener;
  unsigned char portbuf[16];
  char filebuf[16];
  static int port = 0;
  int i;
  FILE *f;





  if ((port < _LOCAL_PORT_MIN) || (port > _LOCAL_PORT_MAX))
      port = _LOCAL_PORT_MIN + (ssh_rand() %
                                (_LOCAL_PORT_MAX - _LOCAL_PORT_MIN));

  /* Allocate and initialize the listener structure. */
  listener = ssh_xmalloc(sizeof(*listener));
  listener->path = ssh_xstrdup(path);
  listener->callback = callback;
  listener->context = context;

  for (i = 0; i < _LOCAL_RETRY_MAX; i++) {
    port++;
    if (port > _LOCAL_PORT_MAX)
      port = _LOCAL_PORT_MIN;



    ssh_snprintf(ssh_sstr(portbuf), sizeof (portbuf), "%d", port);
    listener->tcplistener = ssh_tcp_make_listener(ssh_custr("127.0.0.1"),
                                                  portbuf,
                                                  -1,
                                                  0,
                                                  NULL,
                                                  ssh_local_listen_callback,
                                                  (void*)listener);
    if (listener->tcplistener)
      break;
  }

  if (!listener->tcplistener) {
    ssh_xfree(listener->path);
    ssh_xfree(listener);
    return NULL;
  }

  f = fopen(ssh_csstr(path), "w");
  if (!f) {
    ssh_xfree(listener->path);
    ssh_xfree(listener);
    return NULL;
  }
  strncpy(filebuf, "STREAM ", sizeof (filebuf));
  ssh_snprintf(&(filebuf[7]) , sizeof (filebuf) - 7, "%05d", port);
  if (fwrite(filebuf, 12, 1, f) != 1) {
    ssh_tcp_destroy_listener(listener->tcplistener);
    fclose(f);
    remove(listener->path);
    ssh_xfree(listener->path);
    ssh_xfree(listener);
    return NULL;
  }
  fclose(f);
  return listener;
}

/* Context structure for connecting to the listener. */

typedef struct SshLocalConnectRec
{
  SshLocalCallback callback;
  void *context;
} *SshLocalConnect;


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
  ssh_tcp_destroy_listener(listener->tcplistener);
/* remove(listener->path); */
  ssh_xfree(listener->path);
  ssh_xfree(listener);
  return;
}

/* User called connection is complete on TCP level.  We now
   call user defined callback. */

static void ssh_local_connect_callback(SshTcpError error,
                                       SshStream stream,
                                       void *context)
{
  SshLocalConnect c = (SshLocalConnect)context;

  c->callback(stream, c->context);
  ssh_xfree(c);
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
  SshLocalConnect connection;
  unsigned char filebuf[16];
  FILE *f;

  f = fopen(ssh_csstr(path), "r");
  if (!f) {
    callback(NULL, context);
    return NULL;
  }
  if (fread(filebuf, 12, 1, f) != 1) {
    callback(NULL, context);
    return NULL;
  }
  filebuf[12] = '\0';
  fclose(f);
  if (memcmp("STREAM ", filebuf, 7) != 0) {
    callback(NULL, context);
    return NULL;
  }
  connection = ssh_xmalloc(sizeof(*connection));
  connection->callback = callback;
  connection->context = context;
  ssh_tcp_connect(ssh_custr("127.0.0.1"),
                  &(filebuf[7]),
                  -1,
                  0,
                  NULL,
                  ssh_local_connect_callback,
                  connection);
  return NULL;
}

#endif /* ! HAVE_SYS_UN_H */
