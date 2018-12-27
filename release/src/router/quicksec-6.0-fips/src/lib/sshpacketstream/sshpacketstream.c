/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility functions for the implementation of packet streams.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshgetput.h"
#include "sshpacketstream.h"
#include "sshpacketint.h"

/* Appends a packet at the end of the buffer as specified by the
   variable-length argument list.  The packet will have the given
   type.  The variable length argument list will be as specified for
   ssh_encode_buffer.  This returns the number of bytes added to the
   buffer. */

size_t ssh_packet_encode(SshBuffer buffer, SshPacketType type, ...)
{
  va_list ap;
  size_t return_size;

  va_start(ap, type);
  return_size = ssh_packet_encode_va(buffer, type, ap);
  va_end(ap);

  return return_size;
}

/* Appends a packet at the end of the buffer as specified by the
   variable-length argument list.  The packet will have the given
   type.  The variable-length argument list will be as specified for
   ssh_encode_buffer_va.  This returns the number of bytes added to
   the buffer. */

size_t ssh_packet_encode_va(SshBuffer buffer,
                            SshPacketType type,
                            va_list ap)
{
  size_t payload_size, original_len;
  unsigned char *p;

  /* Save the original length so we can later find where the packet
     header starts. */
  original_len = ssh_buffer_len(buffer);

  /* Construct the packet header with dummy length. */
  if (ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(0),
                        SSH_ENCODE_CHAR(type),
                        SSH_FORMAT_END) > 0)
    {
      /* Encode the packet payload. */
      payload_size = ssh_encode_buffer_va(buffer, ap);

      if (!payload_size)
        return 0;

      /* Update the packet header to contain the correct payload size. */
      p = ssh_buffer_ptr(buffer);

      if (!p)
        return 0;

      p += original_len;
      SSH_PUT_32BIT(p, payload_size + 1);

      /* Return the total number of bytes added to the buffer. */
      return ssh_buffer_len(buffer) - original_len;
    }
  return 0;
}
