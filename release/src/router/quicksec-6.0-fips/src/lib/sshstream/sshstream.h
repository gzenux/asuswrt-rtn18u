/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A generic bidirectional data stream with a callback-based interface.
*/

#ifndef SSHSTREAM_H
#define SSHSTREAM_H

/* Data type for a stream. */
typedef struct SshStreamRec *SshStream;

/* Notifications given by the stream to the application. */
typedef enum {
  /* The stream has data available for reading.  This notification is
     only given if read has previously returned an error. */
  SSH_STREAM_INPUT_AVAILABLE,

  /* The stream is able to write more data for writing.  This notification
     is only given if write has previously returned an error. */
  SSH_STREAM_CAN_OUTPUT,

  /* The stream has been broken/disconnected (e.g., network goes
     down).  This notification is normally not received until
     something unusual happens.  For some streams, the fact that the
     stream has been disconnected may not be detected until a read
     and/or write is attempted.  In such cases, the read/write will
     return an error, and this event will be delivered after the event
     handler returns.  No other events will be delivered after this
     event.  Note that this event is not sent for normal EOF
     conditions, and applications should not rely on receiving this
     instead of just EOF. */
  SSH_STREAM_DISCONNECTED
} SshStreamNotification;

/* Type of the callback called by the stream to notify the application of
   events of interest. */
typedef void (*SshStreamCallback)(SshStreamNotification notification,
                                  void *context);

/* Statistics data returned by the stream. */
typedef struct {
  SshUInt64 read_bytes;
  SshUInt64 written_bytes;
} *SshStreamStats, SshStreamStatsStruct;

/* This structure contains the methods supported by streams.  A stream
   must implement all of these.  This structure is not visible to
   applications; it is implemented and filled by implementations of specific
   stream types.  The stream types have their own creation functions that
   call ssh_stream_create with this table as an argument. */
typedef struct {
  /* Implements the read operation. */
  int (*read)(void *context, unsigned char *buf, size_t size);

  /* Implements the write operation. */
  int (*write)(void *context, const unsigned char *buf, size_t size);

  /* Indicates that the application will not write anymore.  EOF is signalled
     to the other side if supported by the underlying mechanism without
     closing the other direction. */
  void (*output_eof)(void *context);

  /* Sets the callback used to notify the application.  The callback may be
     NULL.  Setting the callback must result in a call to the callback
     when any data is available (as if read and write had both failed). */
  void (*set_callback)(void *context, SshStreamCallback callback,
                       void *callback_context);

  /* Destroys the stream context.  The actual freeing should be done from
     the bottom of the event loop. */
  void (*destroy)(void *context);

} *SshStreamMethods, SshStreamMethodsStruct;


/* Creates a stream.  This is usually not called directly by applications;
   instead, applications call stream type specific creation functions that
   will eventually call this. ssh_stream_create() returns NULL if
   there is insufficient memory available. */
SshStream
ssh_stream_create(const SshStreamMethodsStruct *methods,
                  void *context);

/* Reads at most `size' bytes to the buffer `buffer'.  Returns 0 if
   EOF is encountered, negative value if the read would block, and
   the number of bytes read if something was read. */
int
ssh_stream_read(SshStream stream, unsigned char *buffer, size_t size);

/* Writes at most `size' bytes from the buffer `buffer'.  Returns 0 if the
   other end has indicated that it will no longer read (this condition is not
   guaranteed to be detected), a negative value if the write would block,
   and the number of bytes written if something was actually written. */
int
ssh_stream_write(SshStream stream, const unsigned char *buffer,
                 size_t size);

/* Signals that the application will not write anything more to the stream. */
void
ssh_stream_output_eof(SshStream stream);

/* Sets the callback that the stream uses to notify the application of
   events of interest.  This function may be called at any time, and
   may be called multiple times.  The callback may be NULL, in which
   case it just won't be called.  Setting the callback to non-NULL
   will result in a call to the callback, latest when something can be
   done.  Applications can rely on doing all I/O in the callback, if
   they wish. */
void
ssh_stream_set_callback(SshStream stream, SshStreamCallback callback,
                        void *context);

/* Retrieves stream statistics. */
void
ssh_stream_get_stats(SshStream stream, SshStreamStats stats);

/* Schedules the stream to be destroyed and freed.  It is safe to call
   this from callbacks.  It is permissible to access the stream until
   returning from the current callback. */
void
ssh_stream_destroy(SshStream stream);

/* Returns the methods table for the stream.  This function is primarily
   used by various stream implementations to determine whether a particular
   stream is of the appropriate type. */
SshStreamMethods ssh_stream_get_methods(SshStream stream);

/* Returns the method context of the stream.  This function is intended
   for use by stream implementations only. */
void *
ssh_stream_get_context(SshStream stream);

/* Returns the private methods of the stream. */
void ssh_stream_set_private_methods(SshStream stream, void *private_methods);

/* Returns the private methods of the stream. */
void *ssh_stream_get_private_methods(SshStream stream);

#endif /* SSHSTREAM_H */
