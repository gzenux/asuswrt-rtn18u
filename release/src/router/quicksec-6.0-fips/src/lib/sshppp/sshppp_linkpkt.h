/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_LINKPKT_H

#define SSH_PPP_LINKPKT_H 1

/*
   Simple structure for handling packets with a fixed
   maximum size
*/

typedef enum {
  SSH_PPP_OK = 1,
  SSH_PPP_EMPTY = 2,
  SSH_PPP_ERROR = 3
} SshIterationStatus;

typedef struct SshPppPktBufferRec
{
  SshUInt8 *buffer;
  unsigned long maxbytes;
  unsigned long nbytes;
  unsigned long offset;
} *SshPppPktBuffer, SshPppPktBufferStruct;


/* Init structure to represent an empty buffer,
   do not free or allocate anything */
void
ssh_ppp_pkt_buffer_uninit(SshPppPktBuffer buf);

/* Init buffer to represent a buffer of size buf_size. Does not
   consider any previous values in the buffer */
Boolean
ssh_ppp_pkt_buffer_init(SshPppPktBuffer buf, unsigned long buf_size);

/* Set size of a buffer to buf_size. Requires that _init() or _uninit()
   has been called previously */

Boolean
ssh_ppp_pkt_buffer_set_size(SshPppPktBuffer buf, unsigned long buf_size);

/* Return 1 if buf represents a non-empty buffer */

Boolean
ssh_ppp_pkt_buffer_isinit(SshPppPktBuffer buf);

/* Allocate an instance to represent a buffer of length buf_size */

SshPppPktBuffer
ssh_ppp_pkt_buffer_create(unsigned long buf_size);

/* Free buf. Requires that buf was allocated using _create() */

void
ssh_ppp_pkt_buffer_free(SshPppPktBuffer buf);

/* Return 1 if buffer does not contain any data (buffer can
   still be allocated) */
Boolean
ssh_ppp_pkt_buffer_isempty(SshPppPktBuffer buf);

/* Return the size of the buffer buf represents */

unsigned long
ssh_ppp_pkt_buffer_get_size(SshPppPktBuffer buf);

/* Return 1 if buffer is full */
Boolean
ssh_ppp_pkt_buffer_isfull(SshPppPktBuffer buf);

/* Clear the buffer of any contents */
void
ssh_ppp_pkt_buffer_clear(SshPppPktBuffer buf);

/* Get the amount of unused space before the contents
   of the buffer */
unsigned long
ssh_ppp_pkt_buffer_get_header(SshPppPktBuffer buf);

/* Get the amount of unused space after the contents
   of the buffer */
unsigned long
ssh_ppp_pkt_buffer_get_trailer(SshPppPktBuffer buf);

/* Get the amount of data stored in the buffer */
unsigned long
ssh_ppp_pkt_buffer_get_contentlen(SshPppPktBuffer buf);

/* Copy len bytes from offset in buf (offset counted from the beginning
   of actual content) to buf */
void
ssh_ppp_pkt_buffer_get_buf(SshPppPktBuffer src_buf,
                           unsigned long offset,
                           SshUInt8 *dst,
                           unsigned long len);

/* Copy data from buffer to buffer */
void
ssh_ppp_pkt_buffer_copy(SshPppPktBuffer dst,
                        SshPppPktBuffer src,
                        unsigned long dst_offset,
                        unsigned long src_offset,
                        unsigned long len);

/* Skip nbytes of content in the buffer (mark as unused) */
void
ssh_ppp_pkt_buffer_skip(SshPppPktBuffer buf, unsigned long nbytes);

/* Add "n" bytes to the offset of data in the buffer. Requires
   that there be no content currently stored in the buffer. Can
   be used to "reserve" space at the beginning. */
void
ssh_ppp_pkt_buffer_offset(SshPppPktBuffer buf, unsigned long offset);

/* Truncate a mesage by removing nbytes from the end */
void
ssh_ppp_pkt_buffer_truncate_rel(SshPppPktBuffer buf, unsigned long nbytes);

/* Truncate a message by setting it's size to nbytes. */
void
ssh_ppp_pkt_buffer_truncate_abs(SshPppPktBuffer buf, unsigned long nbytes);

/* Copy the structure src to dst. This does NOT copy the actual buffer,
   the two structures will share the same buffer. */
SshPppPktBuffer
ssh_ppp_pkt_buffer_save(SshPppPktBuffer dst,
                        SshPppPktBuffer src);

/* Allocate a new instance and a buffer for it, and copy the contents
   from src to this new instance. */
SshPppPktBuffer
ssh_ppp_pkt_buffer_dup(SshPppPktBuffer src);


/* Get a pointer to len bytes of data, at offset offset in the
   contents of buf */
SshUInt8*
ssh_ppp_pkt_buffer_get_ptr(SshPppPktBuffer buf,
                           unsigned long offset,
                           unsigned long len);

/* Destroy any "unused" space in the buffer before the
   actual content, and move the content in the buffer
   to offset 0. */
void
ssh_ppp_pkt_buffer_consume_header(SshPppPktBuffer buf);

/* Consume data from within the actual content in the buffer.
   The content bytes at [offset,len] of the actual content
   are destroyed. */
void
ssh_ppp_pkt_buffer_consume(SshPppPktBuffer buf,
                           unsigned long offset,
                           unsigned long len);


/* Functions for inserting, adding, prepending integers into
   the buffer. All functions perform network<->host byte
   order converion, if necessary. */

SshUInt8
ssh_ppp_pkt_buffer_get_uint8(SshPppPktBuffer buf,
                             unsigned long offest);

SshUInt16
ssh_ppp_pkt_buffer_get_uint16(SshPppPktBuffer buf, unsigned long offset);

SshUInt32
ssh_ppp_pkt_buffer_get_uint32(SshPppPktBuffer buf, unsigned long offset);

void
ssh_ppp_pkt_buffer_set_uint8(SshPppPktBuffer buf, unsigned long offset,
                             SshUInt8 val);

void
ssh_ppp_pkt_buffer_insert(SshPppPktBuffer buf,
                          unsigned long offset,
                          unsigned long count);

void
ssh_ppp_pkt_buffer_insert_uint8(SshPppPktBuffer buf,
                                unsigned long offset, SshUInt8 val);

void
ssh_ppp_pkt_buffer_prepend_uint8(SshPppPktBuffer buf, SshUInt8 val);

void
ssh_ppp_pkt_buffer_prepend_uint16(SshPppPktBuffer buf, SshUInt16 val);

void
ssh_ppp_pkt_buffer_prepend_uint32(SshPppPktBuffer buf, SshUInt32 val);

void
ssh_ppp_pkt_buffer_append_uint8(SshPppPktBuffer buf,SshUInt8 val);

void
ssh_ppp_pkt_buffer_append_buf(SshPppPktBuffer buf,
                              SshUInt8 *src_buf,
                              unsigned long len);

void
ssh_ppp_pkt_buffer_append_uint16(SshPppPktBuffer buf, SshUInt16 val);

void
ssh_ppp_pkt_buffer_append_uint32(SshPppPktBuffer buf, SshUInt32 val);

#endif /* SSH_PPP_LINKPKT_H */
