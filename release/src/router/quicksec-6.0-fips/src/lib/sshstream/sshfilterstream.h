/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An object for filtering a data stream bidirectionally.  The object
   allows callbacks to modify and filter data bidirectionally, and allow
   them to disconnect the connection.
*/

#ifndef SSHFILTERSTREAM_H
#define SSHFILTERSTREAM_H

#include "sshstream.h"
#include "sshbuffer.h"

/* Operation codes returned by filter functions.  */

/* Indicates that the given number of bytes should be passed through.
   The number should not be greater than the number of bytes in the
   buffer (minus the offset).  The value zero indicates to keep all
   bytes in the buffer. If ``nbytes'' is less than the number of bytes
   in buffer, the remaining bytes are kept in the buffer. In any case,
   this return code will result in another call to the filter function
   immediately after the return to the eventloop even if no new data
   has been received. */
#define SSH_FILTER_ACCEPT(nbytes)  (nbytes)

/* Instructs to keep the data in buffer, and call the filter again when
   more data has been received. This is different from accepting zero
   bytes. */
#define SSH_FILTER_HOLD            -1

/* Indicates that the stream should be immediately disconnected.  All bytes
   in the buffer are thrown away, and EOF will be returned by the stream
   in both directions.  No more data will be accepted.  The filter functions
   will not be called again (but ``destroy'' will be called when the
   application closes the stream). */
#define SSH_FILTER_DISCONNECT      -2

/* Indicates that the stream should be shortcircuited in both directions.
   Data still in buffers is flushed in both directions, and from then on,
   any data will be directly transmitted through.  The filter functions
   will not be called again (but ``destroy'' will be called when the
   application closes the stream). */
#define SSH_FILTER_SHORTCIRCUIT    -3

/* Function for accessing the data to be filtered. This should be called
   after the filter stream has called the filter function.
   There are three parameter returns: ``data_ret'' for returning the
   buffer containing the data, ``offset_ret'' for returning the
   offset in the buffer and ``eof_received_ret'' for EOF status. */
typedef void (*SshFilterGetCB)(void *internal_context,
                               SshBuffer *data_ret,
                               size_t *offset_ret,
                               Boolean *eof_received_ret);

/* Function for returning the results to the filter stream.
   ``operation'' must be one of the operation codes described
   above.
   There must always be a corresponding call to the completion
   function for every call to the filter function. */
typedef void (*SshFilterCompletionCB)(void *internal_context,
                                      SshInt32 operation);

/* Filter function. The filter stream will call this function for
   every piece of data passing to/from the stream (two different
   function pointers must be given when creating the filter, one will
   be called for outbound data and one for inbound). ``context'' is
   the context given to the function ``ssh_stream_filter_create''.
   ``get_data'' is the function the application must call to access
   the piece of data to be filtered. ``completed'' is the function
   the application must call to pass the piece of data along the
   stream. ``internal_context'' is a pointer required by the two
   abovementioned functions. */
typedef void (*SshFilterProc)(void *context,
                              SshFilterGetCB get_data,
                              SshFilterCompletionCB completed,
                              void *internal_context);

/* Creates a stream that can be used to filter data to/from another
   stream.  ``stream'' is an already existing stream whose data is to
   be filter.  It is wrapped into the filter stream, and will be
   closed automatically when the filter stream is closed.
   ``to_stream_filter'', if non-NULL, is a filter to call whenever
   data is written to the returned stream (and is on its way to
   ``stream'').  ``from_stream_filter'' (if non-NULL) is called
   whenever data is received from ``stream''.  ``destroy'' (if
   non-NULL) is called when the returned stream is closed; it can be
   used to free ``context''.  The filter functions must ensure that the
   buffer does not grow unboundedly.
     `stream'             stream whose data is to be filtered
     `max_buffer_size'    maximum number of bytes to buffer
     `to_stream_filter'   filter for data going to ``stream'', or NULL
     `from_stream_filter' filter for data coming from ``stream'', or NULL
     `destroy'            called when the returned stream is closed, or NULL
     `context'            context argument to pass to the functions.
   The filter functions are not allowed to directly destroy the stream. */
SshStream ssh_stream_filter_create(SshStream stream,
                                   size_t max_buffer_size,
                                   SshFilterProc to_stream_filter,
                                   SshFilterProc from_stream_filter,
                                   void (*destroy)(void *context),
                                   void *context);

#endif /* SSHFILTERSTREAM_H */
