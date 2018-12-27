/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility functions for transferring packets over a SshStream.  This
   basically provides functions for a SshStream implementation that
   communicates using packets, and for a wrapper that takes a SshStream
   and communicates with the other end using packets.  This module takes
   care of packetizing, depacketizing, buffering, flow control, draining
   buffers, and related details, reducing the burden of implementing
   packet-based communication significantly.
*/

#ifndef SSHPACKETSTREAM_H
#define SSHPACKETSTREAM_H

#include "sshbuffer.h"
#include "sshstream.h"

/***********************************************************************
 * Shared definitions.
 ***********************************************************************/

/* Packet type.  Packet types can be numbers 0...255 (i.e., 8 bits). */
typedef unsigned int SshPacketType;

/* This callback is called whenever a packet is received from the
   stream.  Packets are only received if the have been allowed by
   ssh_packet_impl_can_receive or ssh_packet_wrapper_can_receive.  Initially,
   receiving is not allowed.  This function should not modify or free
   `data'. */
typedef void (*SshPacketReceiveProc)(SshPacketType type,
                                     const unsigned char *data, size_t len,
                                     void *context);

/* Notifies that EOF has been received.  No more packets will be received
   from this stream.  This should normally cause the stream or wrapper to be
   closed. */
typedef void (*SshPacketEofProc)(void *context);

/* This is called whenever more data can be sent.  This is only called if
   a previous call to ssh_packet_impl_can_send or ssh_packet_wrapper_can_send
   has returned FALSE. */
typedef void (*SshPacketCanSendProc)(void *context);

/**********************************************************************
 * Functions for using a SshStream object for packet-based
 * communications.  These functions convert the SshStream object to
 * a set of function calls and callbacks that make it easy to send
 * and receive packets.
 **********************************************************************/

/* Data type for the packet stream wrapper. */
typedef struct SshPacketWrapperRec *SshPacketWrapper;

/* Creates a packet stream wrapper around the given stream.
   This returns a wrapper handle.  The handle should be destroyed with
   ssh_packet_wrapper_destroy when no longer needed.  This takes over the
   stream, and the stream will be automatically closed when the wrapper
   is destroyed.  It is not legal to access the stream directly.
      `stream'               stream to lower-level protocol (or network)
      `received_packet'      called when a packet is received
      `received_eof'         called when EOF is received
      `can_send'             called when we can send after not being able to
      `context'              passed as argument to callbacks

   Any of the functions can be NULL if not needed.  It is guaranteed that
   the callbacks will not be called until from the bottom of the event
   loop.  This gives the caller a chance to store the returned pointer
   somewhere before one of the callbacks gets called.  Destroying the
   SshPacketWrapper object is legal in any callback.

   The stream will be ready to receive packets immediately.  If receiving
   packets immediately is not desirable, ssh_packet_wrapper_can_receive
   should be called immediately after creation to prevent receiving
   packets. This function returns NULL if the packet wrapper could not
   be created. */
SshPacketWrapper ssh_packet_wrap(SshStream stream,
                                 SshPacketReceiveProc received_packet,
                                 SshPacketEofProc received_eof,
                                 SshPacketCanSendProc can_send,
                                 void *context);

/* Sets the maximum allowed input packet size for the wrapper. If the
   wrapper is to receive packets longer than specified here, the
   offending packet stream is closed (and the eof-callback is called).
   If this function is not called, the default maximum packet size is
   65k bytes. */
void ssh_packet_wrapper_set_maxpacket(SshPacketWrapper wrapper,
                                      size_t max_packet_size);

/* Destroys the wrapper object, and closes the underlying stream.  None
   of the callbacks will be called after this has been called.  Any
   buffered data will be sent out before the stream is actually
   closed.  The wrapper pointer and the stream object will be invalid after
   this has been called. */
void ssh_packet_wrapper_destroy(SshPacketWrapper wrapper);

/* Informs the packet stream wrapper whether `received_packet' can be
   called.  This is used for flow control. */
void ssh_packet_wrapper_can_receive(SshPacketWrapper wrapper, Boolean status);

/* Sends EOF to the packet stream (after sending out any buffered data).
   It is illegal to send any packets after calling this. */
void ssh_packet_wrapper_send_eof(SshPacketWrapper wrapper);

/* Returns TRUE if it is OK to send more data.  It is not an error to
   send small amounts of data (e.g. a disconnect) when this returns
   FALSE, but sending lots of data when this returns FALSE will
   eventually cause packets to be lost.  To give a specific value, it
   is OK to send 10000 bytes after this starts returning FALSE (this
   provision exists to avoid checks in every disconnect and debug
   message). */
Boolean ssh_packet_wrapper_can_send(SshPacketWrapper wrapper);

/* Sends a packet to the underlying stream.  The packet may actually
   get buffered and sent later.  Packets will always get sent in
   sequence.  The application should use ssh_packet_wrapper_can_send
   and the `can_send' callback to implement flow control. This routine
   returns FALSE if the packet could not be encoded and sent/queued,
   TRUE on success. */
Boolean ssh_packet_wrapper_send(SshPacketWrapper wrapper, SshPacketType type,
                                const unsigned char *data, size_t len);

/* Sends a packet to the underlying stream.  The payload will be
   encoded as specified for ssh_encode_buffer. This routine returns
   FALSE if the packet could not be encoded and sent/queued, TRUE on
   success. */
Boolean ssh_packet_wrapper_send_encode(SshPacketWrapper wrapper,
                                       SshPacketType type,
                                       ...);

/* Sends a packet to the underlying stream.  The payload will be
   encoded as specified for ssh_encode_buffer_va. This routine returns
   FALSE if the packet could not be encoded and sent/queued, TRUE on
   success.*/
Boolean ssh_packet_wrapper_send_encode_va(SshPacketWrapper wrapper,
                                          SshPacketType type,
                                          va_list va);

/* These ssh_packet_wrapper_set_callbacks() function is meant to be
   used in the situation, where a SshPacketWrapper object needs to be
   shared by two (or more) different modules. Ie. a module initializes
   something, doesn't need the SshPacketWrapper anymore, but the
   object can't be destroyed because of the underlying streams, which
   are needed in other operations etc. This function allow for the
   object to be used by some other module than the original, and
   neither module needn't know about the internals of the other. */
void ssh_packet_wrapper_set_callbacks(SshPacketWrapper wrapper,
                                      SshPacketReceiveProc received_packet,
                                      SshPacketEofProc received_eof,
                                      SshPacketCanSendProc can_send,
                                      void *context);

/* Callback for ssh_packet_wrapper_rewrap. */
typedef SshStream (*SshPacketRewrapProc)(SshStream stream,
                                         void *context);

/* This function requests that as soon as the internal send buffer is
   empty, the underlying stream should be wrapped into another stream
   before continuing to receive.  This function schedules a call to
   the `wrap_cb' callback as soon as buffers are empty.  This prevents
   reading from the underlying stream until the `wrap_cb' has been
   called.  The `wrap_cb' should return a valid stream or NULL; if it
   returns NULL, it is interpreted as an error, and `received_eof'
   will be called for the wrapper.  The typical use of this function
   would be to initiate TLS on a packet-wrapped connection in the
   middle of the connection.  It is expected that if `wrap_cb' returns
   non-NULL, it will free (or possibly has freed) the old stream.
   Otherwise the packet wrapper will free the old stream. */
void ssh_packet_wrapper_rewrap(SshPacketWrapper wrapper,
                               SshPacketRewrapProc wrap_cb,
                               void *context);

/************************************************************************
 * Functions for implementing an SshStream object that communicates
 * using packets.
 ************************************************************************/

/* Notifies that the stream is being closed.  After this callback returns,
   the packet stream is automatically destroyed.  No further calls will be
   made to any of its callbacks.  This should not explicitly close the packet
   stream that this is implementing (it has already been destroyed when this
   is called). */
typedef void (*SshPacketImplDestroyProc)(void *context);

/* Creates and initializes a packet stream implemented by the supplied
   functions.  This returns a packet stream object ready for communication.
      `received_packet'       called when a packet is received
      `received_eof'          called when EOF is received
      `can_send'              called when can send after not being able to
      `destroy'               called when we are destroyed
      `context'               passed as argument to callbacks

   It is guaranteed that after creation the callbacks won't be called until
   from the bottom of the event loop (thus, the caller will have a chance to
   store the stream pointer somewhere).  Any of the functions can be NULL if
   not needed.  It is illegal to destroy the stream from the callbacks (this is
   usually not a problem, since only the application will normally call
   ssh_stream_destroy for this).  The `can_send' callback will be called once
   after creation even without ssh_packet_impl_can_send having being called.

   The stream will be ready to receive packets immediately.  If receiving
   packets immediately is not desirable, ssh_packet_impl_can_receive
   should be called immediately after creation to prevent receiving
   packets. This function returns NULL if the packet wrapper could not
   be created. */
SshStream ssh_packet_impl_create(SshPacketReceiveProc received_packet,
                                 SshPacketEofProc received_eof,
                                 SshPacketCanSendProc can_send,
                                 SshPacketImplDestroyProc destroy,
                                 void *context);

/* Informs the packet stream implementation code whether we are willing receive
   packets (i.e., callbacks to the received_packet callback).
   If `enable' is TRUE, we are willing to receive packets.  If it is FALSE,
   `received_packet' will not be called.  This will eventually cause writes
   to the stream fail ("block") until receives are again enabled. */
void ssh_packet_impl_can_receive(SshStream packet_stream, Boolean enable);

/* Causes an EOF to be signalled to anyone reading from the stream (after
   sending any data that has already been buffered).  It is illegal to
   send packets after sending EOF.  Sending an EOF does not affect
   receives. */
void ssh_packet_impl_send_eof(SshStream packet_stream);

/* Returns TRUE if the packet stream can take more packets.  If this
   returns FALSE, and the `can_send' callback is non-NULL, the
   `can_send' callback will be called when packets can again be sent.

   It is not strictly an error to send packets after this has returned
   FALSE.  However, if too much data is sent, packets may eventually
   be ignored.  To give a specific value, sending at most 10000 bytes
   after this returns FALSE will always succeed (this provision exists
   to avoid checks in every disconnect or debug messages). */
Boolean ssh_packet_impl_can_send(SshStream packet_stream);

/* Sends a packet to the stream.  The packet is actually buffered, and
   the higher level is signalled that data is available.  The higher
   level will read the data when convenient.  The application should
   use ssh_packet_impl_can_send and the `can_send' callback to
   implement flow control.  This should only be called when
   ssh_packet_impl_can_send returns TRUE (see notes in that
   function). */
void ssh_packet_impl_send(SshStream packet_stream, SshPacketType type,
                          const unsigned char *data, size_t len);

/* Sends a packet to the stream, encoding the payload of the packet
   as specified for ssh_encode_buffer. */
void ssh_packet_impl_send_encode(SshStream packet_stream,
                                 SshPacketType type,
                                 ...);

/* Sends a packet to the stream, encoding the payload of the packet
   as specified for ssh_encode_buffer_va. */
void ssh_packet_impl_send_encode_va(SshStream packet_stream,
                                    SshPacketType type,
                                    va_list va);

/**********************************************************************
 * Special functions for applications requiring special handling.
 **********************************************************************/

/* Causes any I/O requests from `packet_stream' (which must be implemented
   using the ssh_impl_* functions in this module) to be shortcircuited to
   the stream inside `wrapper', and vice versa.  The `received_packet',
   `received_eof', and `can_send' callbacks will no longer be called for
   either object.  This will automatically allow sends/receives in each
   direction as appropriate.  This can only be called from a SshPacketWrapper
   `received_packet' callback.

   The `destroy' callback is not shortcircuited, and should destroy the
   wrapper and any other data that might have been allocated.

   The primary purpose is to allow a protocol module (e.g., an authentication
   module) to shortcircuit any traffic through it. */
void ssh_packet_shortcircuit(SshStream packet_stream,
                             SshPacketWrapper wrapper);

#endif /* SSHPACKETSTREAM_H */
