/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Plug two streams together.
*/

#ifndef __SSHSTREAMCONNECT_H__
#define __SSHSTREAMCONNECT_H__

#include "sshstream.h"
#include "sshoperation.h"

/* Stream close strategy. */
typedef enum
{
  /* Close the streams when both directions have flushed all data and
     they have received EOF on their input stream. */
  SSH_STREAM_CONNECT_CLOSE_ON_EOF = 0,

  /* Close when one direction has flushed all data and it has received
     EOF on its input stream. */
  SSH_STREAM_CONNECT_CLOSE_ON_PEER_EOF
} SshStreamConnectCloseStrategy;

/* Parameters for stream connect object. */
struct SshStreamConnectParamsRec
{
  /* How the stream connect object is closed.  This defaults to
     SSH_STREAM_CONNECT_CLOSE_ON_EOF. */
  SshStreamConnectCloseStrategy close_strategy;
  /* If TRUE, data is only sent from `s1' to `s2'.  If FALSE, data is
     copied both ways. */
  Boolean one_way;
};

typedef struct SshStreamConnectParamsRec SshStreamConnectParamsStruct;
typedef struct SshStreamConnectParamsRec *SshStreamConnectParams;

/* Status codes for a stream connect operation. */
typedef enum
{
  SSH_STREAM_CONNECT_OK = 0,
  SSH_STREAM_CONNECT_FAILURE = 1,
  SSH_STREAM_CONNECT_ERROR_STREAM_ERROR = 2,
  SSH_STREAM_CONNECT_ERROR_OUT_OF_MEMORY = 3
} SshStreamConnectStatus;

/* A callback function of this type is called to notify the completion
   status of a stream connect operation. */
typedef void (*SshStreamConnectClosedCB)(SshStreamConnectStatus status,
                                         void *context);

/* Connect two streams `s1' and `s2' together so that all data
   transmitted in both streams is sent to the other stream.  The
   argument `params' specify optional parameters for the stream
   connect object.  If the argument `params' has the value NULL or any
   of its fields have the value NULL or 0, the default values will be
   used for those parameters.  The function calls the callback
   function `callback' to notify about the completion of the
   operation.  You can also use the returned Sshoperationhandle to
   cancel an active stream connect operation.  The function consumes
   the streams `s1' and `s2'.  It will destroy the streams both in
   success and failure cases.  You must not use or free them after
   this call returns. */
SshOperationHandle ssh_stream_connect_streams(
                                SshStream s1,
                                SshStream s2,
                                SshStreamConnectParams params,
                                SshStreamConnectClosedCB callback,
                                void *context);

#endif /* ! __SSHSTREAMCONNECT_H__ */
/* eof (sshstreamconnect.h) */
