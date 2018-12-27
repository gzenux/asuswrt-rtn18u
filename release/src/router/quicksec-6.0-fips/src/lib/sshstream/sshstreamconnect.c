/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Plug two streams together.
*/

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshtimeouts.h"
#include "sshstreamconnect.h"

#define SSH_DEBUG_MODULE "SshStreamConnect"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshStreamConnect"

/* An I/O structure for unidirectional stream connection. */
struct SshStreamConnectIORec
{
  /* Flags. */
  unsigned int active : 1;      /* Thread active. */
  unsigned int terminate : 1;   /* Terminate when already read data
                                   has been flushed. */
  unsigned int aborted : 1;     /* Operation aborted. */

  /* Source stream. */
  SshStream from;

  /* Destination stream. */
  SshStream to;

  /* Buffer for data being copied. */
  unsigned char buf[1024];
  size_t data_in_buf;
  size_t bufpos;

  /* The stream connection object to which this IO structure belongs
     to. */
  struct SshStreamConnectRec *connect;
};

typedef struct SshStreamConnectIORec SshStreamConnectIOStruct;
typedef struct SshStreamConnectIORec *SshStreamConnectIO;

/* A stream connection object. */
struct SshStreamConnectRec
{
  /* FSM handling the connect operation. */
  SshFSMStruct fsm;

  /* Parameters for the object. */
  SshStreamConnectParamsStruct params;

  /* Operation handle that was passed to the user. */
  SshOperationHandle handle;

  /* Thread copying data form source to destination. */
  SshFSMThreadStruct thread_s;
  SshStreamConnectIOStruct io_s;

  /* Thread copying data form destination to source. */
  SshFSMThreadStruct thread_d;
  SshStreamConnectIOStruct io_d;

  /* Completion callback and its context data. */
  SshStreamConnectClosedCB callback;
  void *callback_context;

  /* The status of the operation. */
  SshStreamConnectStatus status;
};

typedef struct SshStreamConnectRec SshStreamConnectStruct;
typedef struct SshStreamConnectRec *SshStreamConnect;


/************************** Static help functions ***************************/

/* A timeout function that handles the stream connect object
   termination. */
static void
ssh_stream_connect_terminate(void *context)
{
  SshStreamConnect conn = (SshStreamConnect) context;

  SSH_ASSERT(!conn->io_s.active);
  SSH_ASSERT(!conn->io_d.active);

  SSH_DEBUG(SSH_D_MIDOK, ("connection between streams %p and %p terminated",
                          conn->io_s.from, conn->io_s.to));

  /* Invalidate operation handle if it is still valid. */
  if (conn->handle)
    ssh_operation_unregister(conn->handle);

  /* Call user callback if it is valid (e.g. the operation was not
     aborted). */
  if (conn->callback)
    (*conn->callback)(conn->status, conn->callback_context);

  /* Uninit connection object. */

  ssh_fsm_uninit(&conn->fsm);

  ssh_stream_destroy(conn->io_s.from);
  ssh_stream_destroy(conn->io_s.to);

  ssh_free(conn);
}

static void
ssh_stream_connect_stream_callback(SshStreamNotification notification,
                                   void *context)
{
  SshStreamConnect conn = (SshStreamConnect) context;

  /* Simply continue all active threads. */
  if (conn->io_s.active)
    ssh_fsm_continue(&conn->thread_s);
  if (conn->io_d.active)
    ssh_fsm_continue(&conn->thread_d);
}


static void
ssh_stream_connect_abort_callback(void *context)
{
  SshStreamConnect conn = (SshStreamConnect) context;

  /* Mark threads aborted. */
  conn->io_s.aborted = 1;
  conn->io_d.aborted = 1;

  /* Clear operation handle since it is not valid after the operation
     was aborted. */
  conn->handle = NULL_FNPTR;

  /* Clear completion callback so it won't get called. */
  conn->callback = NULL_FNPTR;

  /* Continue threads. */
  ssh_stream_connect_stream_callback(SSH_STREAM_INPUT_AVAILABLE, conn);
}


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_stream_connect_st_wait_input);
SSH_FSM_STEP(ssh_stream_connect_st_write_data);
SSH_FSM_STEP(ssh_stream_connect_st_terminate);


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_stream_connect_st_wait_input)
{
  SshStreamConnectIO io = (SshStreamConnectIO) thread_context;
  int read;

  /* First, check if the operation was aborted. */
  if (io->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_stream_connect_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  read = ssh_stream_read(io->from, io->buf, sizeof(io->buf));

  if (read < 0)
    {
      /* We would block.  But first, check if we should terminate. */
      SSH_DEBUG(SSH_D_MIDOK, ("read %p would block", io->from));
      if (io->terminate)
        {
          /** Shutting down. */
          SSH_FSM_SET_NEXT(ssh_stream_connect_st_terminate);
          return SSH_FSM_CONTINUE;
        }

      return SSH_FSM_SUSPENDED;
    }
  else if (read == 0)
    {
      /** EOF. */
      /* Signal that we won't write any more data. */
      SSH_DEBUG(SSH_D_MIDOK, ("read %p returns eof, outputting eof to %p",
                              io->from, io->to));
      ssh_stream_output_eof(io->to);
      SSH_FSM_SET_NEXT(ssh_stream_connect_st_terminate);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("read %p returns %u, signaling write to %p",
                              io->from, (unsigned int)read, io->to));
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("read buffer (%d bytes):", read),
                        io->buf, read);
      io->data_in_buf = read;
      SSH_FSM_SET_NEXT(ssh_stream_connect_st_write_data);
    }

  return SSH_FSM_CONTINUE;

}

SSH_FSM_STEP(ssh_stream_connect_st_write_data)
{
  SshStreamConnectIO io = (SshStreamConnectIO) thread_context;
  int wrote;

  SSH_ASSERT(io->data_in_buf);
  SSH_ASSERT(io->bufpos < io->data_in_buf);

  /* First, check if the operation was aborted. */
  if (io->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_stream_connect_st_terminate);
      return SSH_FSM_CONTINUE;
    }

  while (io->bufpos < io->data_in_buf)
    {
      wrote = ssh_stream_write(io->to, io->buf + io->bufpos,
                               io->data_in_buf - io->bufpos);
      if (wrote < 0)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("write %p would block", io->to));
          return SSH_FSM_SUSPENDED;
        }
      else if (wrote == 0)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("write to %p returns error", io->to));
          io->connect->status = SSH_STREAM_CONNECT_ERROR_STREAM_ERROR;
          SSH_FSM_SET_NEXT(ssh_stream_connect_st_terminate);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("wrote %u bytes to %p",
                                  (unsigned int)wrote, io->to));
          io->bufpos += wrote;
        }
    }

  SSH_ASSERT(io->bufpos >= io->data_in_buf);
  io->bufpos = 0;
  io->data_in_buf = 0;

  /** Data written. */
  SSH_FSM_SET_NEXT(ssh_stream_connect_st_wait_input);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_stream_connect_st_terminate)
{
  SshStreamConnectIO io = (SshStreamConnectIO) thread_context;
  SshStreamConnect conn = io->connect;

  /* This thread is finished. */
  io->active = 0;

  /* Check if we were the last thread in the connection. */
  if (!conn->io_s.active && !conn->io_d.active)
    {
      /* Yes we were.  Let's register a timeout to destroy the connect
         object. */
      ssh_xregister_timeout(0, 0, ssh_stream_connect_terminate, conn);
    }
  else
    {
      /* No we are not.  Check the close strategy. */
      switch (conn->params.close_strategy)
        {
        case SSH_STREAM_CONNECT_CLOSE_ON_EOF:
          /* Wait until both ends see the EOF.  Nothing here. */
          break;

        case SSH_STREAM_CONNECT_CLOSE_ON_PEER_EOF:
          /* Close when EOF is seen on one direction.  Let's notify
             our peer. */
          conn->io_s.terminate = 1;
          conn->io_d.terminate = 1;

          /* We are very lazy and we will call the notification
             callback.  It will wake up the other (active) thread. */
          ssh_stream_connect_stream_callback(SSH_STREAM_INPUT_AVAILABLE, conn);
          break;
        }
    }

  /* And terminate. */
  return SSH_FSM_FINISH;
}


/************************ Public interface functions ************************/

SshOperationHandle
ssh_stream_connect_streams(SshStream s1, SshStream s2,
                           SshStreamConnectParams params,
                           SshStreamConnectClosedCB callback, void *context)
{
  SshStreamConnect conn = NULL;

  conn = ssh_calloc(1, sizeof(*conn));
  if (conn == NULL)
    goto error;

  conn->handle = ssh_operation_register(ssh_stream_connect_abort_callback,
                                        conn);
  if (conn->handle == NULL)
    goto error;

  if (params)
    conn->params = *params;

  ssh_fsm_init(&conn->fsm, conn);
  conn->callback = callback;
  conn->callback_context = context;
  conn->status = SSH_STREAM_CONNECT_OK;

  /* Setup IO threads. */

  conn->io_s.active = 1;
  conn->io_s.from = s1;
  conn->io_s.to = s2;
  conn->io_s.connect = conn;

  ssh_fsm_thread_init(&conn->fsm, &conn->thread_s,
                      ssh_stream_connect_st_wait_input,
                      NULL_FNPTR, NULL_FNPTR, &conn->io_s);

  if (params != NULL && !params->one_way)
    {
      conn->io_d.active = 1;
      conn->io_d.from = s2;
      conn->io_d.to = s1;
      conn->io_d.connect = conn;

      ssh_fsm_thread_init(&conn->fsm, &conn->thread_d,
                          ssh_stream_connect_st_wait_input,
                          NULL_FNPTR, NULL_FNPTR, &conn->io_d);
    }
  else
    {
      conn->io_d.active = 0;
    }

  /* Set stream callbacks. */
  ssh_stream_set_callback(s1, ssh_stream_connect_stream_callback, conn);
  ssh_stream_set_callback(s2, ssh_stream_connect_stream_callback, conn);

  /* All done. */
  return conn->handle;


  /* Error handling. */

 error:

  /* We consume the streams. */
  ssh_stream_destroy(s1);
  ssh_stream_destroy(s2);

  if (conn)
    ssh_free(conn);

  if (callback)
    (*callback)(SSH_STREAM_CONNECT_ERROR_OUT_OF_MEMORY, context);

  return NULL;
}
