/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A pair of streams connected to each other, like a bidirectional pipe.  This
   is mostly used for testing.
*/

#ifndef SSHSTREAMPAIR_H
#define SSHSTREAMPAIR_H

#include "sshstream.h"

/* Creates a pair of streams so that everything written on one stream
   will appear as output from the other stream. On failure to create the
   pair of streams *stream1_return and *stream1_return are both
   returned as NULL. */
void ssh_stream_pair_create(SshStream *stream1_return,
                            SshStream *stream2_return);

#endif /* SSHSTREAMPAIR_H */
