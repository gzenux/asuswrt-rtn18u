/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshdatastream.h
*/

/* Wrap up the data buf into a stream. The resulting stream will be a
   read only stream. */
#ifndef SSHDATASTREAM_H_INCLUDED
#define SSHDATASTREAM_H_INCLUDED

#include "sshstream.h"
#include "sshbuffer.h"

/* Create a stream to return the `len' bytes of data `data'.  The
   argument `static_data' specifies whether the data `data' is static
   or not.  If the data is static, the value pointed by `data' must
   remain valid as long as the returned stream object is alive. */
SshStream ssh_data_stream_create(const unsigned char *data, size_t len,
                                 Boolean static_data);

/* Create a data stream using the buffer `buffer'.  The input buffer
   must not be accessed after this call, it becomes part of the stream
   object and is freed when the stream is destroyed. */
SshStream ssh_data_stream_create_buffer(SshBuffer buffer);

#endif /* SSHDATASTREAM_H_INCLUDED */
