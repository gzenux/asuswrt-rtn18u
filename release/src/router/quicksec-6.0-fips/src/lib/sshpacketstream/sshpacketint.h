/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Private definitions for packet streams.
*/

#ifndef SSHPACKETINT_H
#define SSHPACKETINT_H

#include "sshpacketstream.h"

/* Appends a packet at the end of the buffer as specified by the
   variable-length argument list.  The packet will have the given
   type.  The variable length argument list will be as specified for
   ssh_encode_buffer.  This returns the number of bytes added to the
   buffer. */
size_t ssh_packet_encode(SshBuffer buffer, SshPacketType type, ...);

/* Appends a packet at the end of the buffer as specified by the
   variable-length argument list.  The packet will have the given
   type.  The variable-length argument list will be as specified for
   ssh_encode_buffer_va.  This returns the number of bytes added to
   the buffer. */
size_t ssh_packet_encode_va(SshBuffer buffer, SshPacketType type,
                            va_list ap);

/* INTERNAL FUNCTION - not to be called from applications.  This
   immediately shortcircuits the up stream downward to the other
   stream.  Directs reads/writes/callbacks directly to it.  The stream
   argument may be NULL to cancel shortcircuiting.  There must be no partial
   incoming packet in impl_stream buffers. */
void ssh_packet_impl_shortcircuit_now(SshStream impl_stream, SshStream stream);


#endif /* SSHPACKETINT_H */
