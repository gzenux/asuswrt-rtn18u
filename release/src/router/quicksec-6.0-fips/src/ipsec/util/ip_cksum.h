/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP header checksum computation.
*/

#ifndef IP_CKSUM_H
#define IP_CKSUM_H

#include "interceptor.h"

/* Computes the complement of the IP checksum over the buffer (i.e.,
   the value that is stored in the checksum field in the IP header).
   The checksum is returned in host byte order.  The buffer size cannot
   be more than 65535 bytes. */
SshUInt16 ssh_ip_cksum(const unsigned char *buf, size_t bytes);

/* Computes the complement of the IP checksum over the specified range
   of the packet.  The checksum is returned in host byte order.  The number
   of bytes cannot be more than 65535. */
SshUInt16 ssh_ip_cksum_packet(SshInterceptorPacket pp, size_t offset,
                              size_t bytes);

/* Update the complement of the IP checksum by having a byte change at
   a specified byte offset.  The input checksum and the returned
   checksum are in host byte order. */
SshUInt16 ssh_ip_cksum_update_byte(SshUInt16 cks, size_t ofs,
                                   SshUInt8 old_value, SshUInt8 new_value);

/* Update the complement of the IP checksum by having a short (16-bit
   value) change at a specified byte offset.  The input checksum and
   the returned checksum are in host byte order.  The old and new
   values are in host byte order, and are assumed to be stored at the
   offset in network byte order. */
SshUInt16 ssh_ip_cksum_update_short(SshUInt16 cks, size_t ofs,
                                    SshUInt16 old_value, SshUInt16 new_value);

/* Update the complement of the IP checksum by having a long (32-bit
   value) change at a specified byte offset.  The input checksum and
   the returned checksum are in host byte order. The old and new
   values are in host byte order, and are assumed to be stored at the
   offset in network byte order. */
SshUInt16 ssh_ip_cksum_update_long(SshUInt16 cks, size_t ofs,
                                   SshUInt32 old_value, SshUInt32 new_value);

/* Compute the upper layer (TCP/UDP) checksum of the packet pp, and
   store the checksum to the packet. 'media_hdrlen' is the byte offset of
   the packet where the IP header begins (i.e. the media header length).
   'ip_hdrlen' is the length of the IP header. This function sets to zero
   any existing checksum in the upper layer before computing the new
   checksum. This function returns TRUE on success and FALSE on failure,
   in which the packet 'pp' is already freed. */
Boolean ssh_ip_cksum_packet_compute(SshInterceptorPacket pp,
                                    size_t media_hdrlen, size_t ip_hdrlen);

#endif /* IP_CKSUM_H */

