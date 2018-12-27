/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"


#define SSH_DEBUG_MODULE "SshIkev2NetWindow"

/*
  Reset window specific things from a packet and finish with the
  packet.
 */
static void
ikev2_window_packet_done(
        SshIkev2Packet packet)
{
  packet->window_next = NULL;
  packet->in_window = 0;

  ikev2_packet_done(packet);
}


/*
  Finish a list of packets linked as a list with window_next pointers.
 */
static void
ikev2_window_packet_list_done(
        SshIkev2Packet first_packet)
{
  SshIkev2Packet next_packet = first_packet;

  while (next_packet != NULL)
    {
      SshIkev2Packet packet = next_packet;

      next_packet = packet->window_next;

      ikev2_window_packet_done(packet);
    }
}


/*
  Compute a hash value of packet data and store it to the packet
  structure.
 */
static void
ikev2_window_packet_hash_compute(
        SshIkev2Packet packet)
{
  SshIkev2 ikev2 = packet->server->context;

  ssh_hash_reset(ikev2->hash);

  ssh_hash_update(
          ikev2->hash,
          packet->encoded_packet,
          packet->encoded_packet_len);

  ssh_hash_final(ikev2->hash, packet->hash);

  SSH_DEBUG_HEXDUMP(
          SSH_D_LOWOK,
          ("Computed hash for packet %p", packet),
          packet->hash, sizeof(packet->hash));
}


/*
  Compare hashes of two packets return TRUE if are equal; FALSE
  otherwise
 */
static Boolean
ikev2_window_packet_hash_equal(
        SshIkev2Packet packet_a,
        SshIkev2Packet packet_b)
{
  if (memcmp(packet_a->hash, packet_b->hash, sizeof (packet_a->hash)) == 0)
    {
      return TRUE;
    }

  return FALSE;
}


/*
  Copy a hash value from one packet structure to another.
 */
static void
ikev2_window_packet_hash_copy(
        SshIkev2Packet dst,
        SshIkev2Packet src)
{
  memcpy(dst->hash, src->hash, sizeof(src->hash));
}



/*
  Encode packet structure to given ssh buffer.
 */
static SshIkev2Error
ikev2_window_encode_packet(
        SshBuffer buffer,
        SshIkev2Packet packet)
{
  size_t offset;

  offset =
      ssh_encode_buffer(
              buffer,
              SSH_ENCODE_UINT32(packet->flags),
              SSH_ENCODE_UINT32(packet->message_id),
              SSH_ENCODE_DATA(packet->hash, sizeof(packet->hash)),
              SSH_ENCODE_UINT32_STR(
                      packet->encoded_packet,
                      packet->encoded_packet_len),
              SSH_FORMAT_END);

  if (offset == 0)
    {
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  return SSH_IKEV2_ERROR_OK;
}


/*
  Decode a packet from buffer buf of length len.  Uses ike_sa to find
  ikev2 context for packet allocation.  On success store pointer to
  allocated and decoded packet to store_p, return number of bytes
  consumed from buffer while decoding in parsed_bytes_p, and return
  SSH_IKEV2_ERROR_OK.

  On error, packet is not allocated, both parsed_bytes_p and
  store_p have undefined values, and an error value is returned.
 */
static SshIkev2Error
ikev2_window_decode_packet(
        SshIkev2Sa ike_sa,
        const char * buf,
        size_t len,
        size_t *parsed_bytes_p,
        SshIkev2Packet *store_p)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2 ikev2 = ike_sa->server->context;
  SshIkev2Packet packet;
  size_t parsed_bytes = 0;
  unsigned char *encoded_packet;
  size_t encoded_packet_len;
  SshUInt32 flags;

  packet = ikev2_packet_allocate(ikev2, NULL_FNPTR);
  if (packet == NULL)
    {
      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      parsed_bytes =
          ssh_decode_array(
                  buf, len,
                  SSH_DECODE_UINT32(&flags),
                  SSH_DECODE_UINT32(&packet->message_id),
                  SSH_DECODE_DATA(packet->hash, sizeof(packet->hash)),
                  SSH_DECODE_UINT32_STR_NOCOPY(
                          &encoded_packet,
                          &encoded_packet_len),
                  SSH_FORMAT_END);

      if (parsed_bytes == 0)
        {
          status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      packet->flags = flags;
      packet->in_window = 1;
      packet->server = ike_sa->server;

      if (encoded_packet_len)
        {
          packet->encoded_packet =
              ssh_memdup(
                      encoded_packet,
                      encoded_packet_len);
          packet->encoded_packet_len = encoded_packet_len;

          if (packet->encoded_packet == NULL)
            {
              status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
        }
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      *parsed_bytes_p = parsed_bytes;
      *store_p = packet;
    }


  if (status != SSH_IKEV2_ERROR_OK)
    {
      if (packet != NULL)
        {
          packet->in_window = 0;
          ikev2_packet_free(ikev2, packet);
        }
    }

  return status;
}

/*
  Initialise transmit window structure.
  Initial window size is 1 and next_message_id 0.
 */
void
ikev2_transmit_window_init(SshIkev2TransmitWindow transmit_window)
{
  transmit_window->next_message_id = 0;
  transmit_window->window_size = 1;
  transmit_window->packets_head = NULL;
  transmit_window->packets_tail = NULL;
  SSH_DEBUG(SSH_D_LOWOK, ("Transmit window %p initialised",
                          transmit_window));
}


/*
  Reset transmit window to initial state; window_size == 1 and
  next_message_id == 0.
 */
void
ikev2_transmit_window_reset(
        SshIkev2TransmitWindow transmit_window)
{
  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Reset; next_message_id %u -> %u; window_size %u -> %u.",
                   transmit_window,
                   transmit_window->next_message_id,
                   0,
                   transmit_window->window_size,
                   1));

  ikev2_transmit_window_flush(transmit_window);

  transmit_window->next_message_id = 0;
  transmit_window->window_size = 1;
}


/*
  Return TRUE is transmit_window is full; FALSE otherwise.
 */
Boolean
ikev2_transmit_window_full(
        SshIkev2TransmitWindow transmit_window)
{
  Boolean full = FALSE;

  if (transmit_window->packets_head != NULL)
    {
      SshUInt32 window_size;

      window_size =
          transmit_window->next_message_id
          - transmit_window->packets_head->message_id;

      SSH_ASSERT(window_size <= transmit_window->window_size);

      if (window_size == transmit_window->window_size)
        {
          full = TRUE;
        }
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Window is %s.",
                   transmit_window,
                   (full ? "full" : "not full")));

  return full;
}


/*
  Assign next_message_id to packet and insert the packet to transmit
  window. On success return SSH_IKEV2_ERROR_OK. Fails when window is
  full returning SSH_IKEV2_ERROR_WINDOW_FULL.
 */
SshIkev2Error
ikev2_transmit_window_insert(
        SshIkev2TransmitWindow transmit_window,
        SshIkev2Packet packet)
{
  SshIkev2Error result = SSH_IKEV2_ERROR_OK;

  if (transmit_window->packets_head == NULL)
    {
      packet->message_id = transmit_window->next_message_id;

      ++transmit_window->next_message_id;

      transmit_window->packets_head = packet;
      transmit_window->packets_tail = packet;
      packet->window_next = NULL;
    }
  else
    {
      SshUInt32 window_size;

      window_size =
          transmit_window->next_message_id
          - transmit_window->packets_head->message_id;

      SSH_ASSERT(window_size <= transmit_window->window_size);

      if (window_size == transmit_window->window_size)
        {
          SSH_DEBUG(
                  SSH_D_LOWOK,
                  ("Transmit window %p: "
                   "Inserting packet %p failed.",
                           transmit_window,
                           packet));

          result = SSH_IKEV2_ERROR_WINDOW_FULL;
        }
      else
        {
          packet->message_id = transmit_window->next_message_id;

          ++transmit_window->next_message_id;

          transmit_window->packets_tail->window_next = packet;
          transmit_window->packets_tail = packet;
          packet->window_next = NULL;
        }
    }

  if (result == SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Transmit window %p: "
               "Inserted packet %p with message_id %u.",
                       transmit_window,
                       packet,
                       packet->message_id));

      packet->in_window = 1;
    }

  return result;
}


/*
   Find a request packet with given message_id from transmit window
   and return pointer to if found. Otherwise, return NULL.
 */
SshIkev2Packet
ikev2_transmit_window_find_request(
        SshIkev2TransmitWindow transmit_window,
        SshUInt32 message_id)
{
  SshIkev2Packet packet;

  for (packet = transmit_window->packets_head;
       packet != NULL && packet->message_id != message_id;
       packet = packet->window_next)
    ;

  if (packet == NULL)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Transmit window %p: No packet with message_id %u.",
                       message_id));
    }
  else if (packet->sent == 0)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Transmit window %p: "
               "Found packet %p with message_id %u; packet not sent yet.",
                       transmit_window,
                       packet,
                       message_id));
      packet = NULL;
    }
  else
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Transmit window %p: "
               "Returning packet %p with message_id %u.",
                       transmit_window,
                       packet,
                       message_id));
    }

  return packet;
}


/*
  Acknowledge given message id to transmit window. This is to be
  called after a response is considered authentic. If a request with
  the same message_id is found within the window it will be removed
  from the window and TRUE is returned. If the message_id acknowledge
  was the smallest message_id in the window the window can accept more
  packets after the call.

  If no request packet with the message_id is found function returns
  FALSE denoting that the request had already been acknowledged with a
  valid response and any new response is likely to be a fast
  retransmit and should not be processed any further.
*/
Boolean
ikev2_transmit_window_acknowledge(
        SshIkev2TransmitWindow transmit_window,
        SshUInt32 message_id)
{
  SshIkev2Packet packet;
  SshIkev2Packet packet_predecessor = NULL;
  Boolean result = FALSE;

  for (packet = transmit_window->packets_head;
       packet != NULL && packet->message_id != message_id;
       packet = packet->window_next)
    {
      packet_predecessor = packet;
    }

  if (packet)
    {
      if (packet == transmit_window->packets_head)
        {
          transmit_window->packets_head = packet->window_next;
        }
      else
        {
          packet_predecessor->window_next = packet->window_next;
        }

      if (packet == transmit_window->packets_tail)
        {
          transmit_window->packets_tail = packet_predecessor;
        }

      ikev2_window_packet_done(packet);

      result = TRUE;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Acknowledging message_id %u: %s.",
                   transmit_window,
                   message_id,
                   result ? "success" : "no such request"));

  return result;
}

/*
  Removes all packets from the window and finishes them.
 */
void
ikev2_transmit_window_flush(
        SshIkev2TransmitWindow transmit_window)
{

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Flushing.",
                   transmit_window));

  ikev2_window_packet_list_done(transmit_window->packets_head);

  transmit_window->packets_head = NULL;
  transmit_window->packets_tail = NULL;
}


/*
   Frees all memory allocated by the window first flushing all packets
   from the window.
 */
void
ikev2_transmit_window_uninit(SshIkev2TransmitWindow transmit_window)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Uninitialising transmit window %p", transmit_window));
  ikev2_transmit_window_flush(transmit_window);
}


/*
  Set new size for transmit window.
 */
SshIkev2Error
ikev2_transmit_window_set_size(
        SshIkev2TransmitWindow transmit_window,
        unsigned int newsize)
{
  if (newsize > SSH_IKEV2_MAX_WINDOW_SIZE)
    {
      newsize = SSH_IKEV2_MAX_WINDOW_SIZE;
    }

  if (newsize < transmit_window->window_size)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Transmit window %p: "
               "Failed to set window size from %u to %u.",
                       transmit_window,
                       transmit_window->window_size,
                       newsize));

      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  if (transmit_window->window_size == newsize)
    {
      /* Silently ignore setting to current value. */
      return SSH_IKEV2_ERROR_OK;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Set window size from %u to %u",
                   transmit_window,
                   transmit_window->window_size,
                   newsize));

  transmit_window->window_size = newsize;

  return SSH_IKEV2_ERROR_OK;
}

/*
  Encode transmit window to a linear memory buffer.
 */
SshIkev2Error
ikev2_transmit_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshBufferStruct buffer;
  SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;
  SshIkev2Packet packet;
  SshUInt32 packet_count = 0;
  size_t offset;

  ssh_buffer_init(&buffer);

  for (packet = transmit_window->packets_head;
       packet != NULL;
       packet = packet->window_next)
    {
      ++packet_count;
    }

  offset =
      ssh_encode_buffer(
              &buffer,
              SSH_ENCODE_UINT32(transmit_window->next_message_id),
              SSH_ENCODE_UINT32(transmit_window->window_size),
              SSH_ENCODE_UINT32(packet_count),
              SSH_FORMAT_END);

  if (offset == 0)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Transmit window %p: "
               "Encode failed: out of memory.",
                       transmit_window));

      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Transmit window %p: "
           "Encoding: next_message_id %u, window_size %u, packets %u.",
                   transmit_window,
                   transmit_window->next_message_id,
                   transmit_window->window_size,
                   (unsigned) packet_count));

  for (packet = transmit_window->packets_head;
       status == SSH_IKEV2_ERROR_OK &&
           packet != NULL;
       packet = packet->window_next)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Transmit window %p: "
               "Encoding packet %p message_id %u.",
                       transmit_window,
                       packet,
                       packet->message_id));

      status =
          ikev2_window_encode_packet(
                  &buffer,
                  packet);
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      *buf = ssh_buffer_steal(&buffer, len);
    }

  ssh_buffer_uninit(&buffer);

  return status;
}


/*
  Establish a new transmit window to given ike_sa decoding its
  contents from given buffer.
 */
SshIkev2Error
ikev2_transmit_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2TransmitWindow transmit_window = ike_sa->transmit_window;
  SshUInt32 packet_count;
  size_t offset = 0;

  ikev2_transmit_window_init(transmit_window);

  offset =
    ssh_decode_array(buf, len,
                     SSH_DECODE_UINT32(&transmit_window->next_message_id),
                     SSH_DECODE_UINT32(&transmit_window->window_size),
                     SSH_DECODE_UINT32(&packet_count),
                     SSH_FORMAT_END);

  if (offset == 0)
    {
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Transmit window %p: "
                 "Decoding: next_message_id %u, window_size %u, packets %u.",
                 transmit_window,
                 transmit_window->next_message_id,
                 transmit_window->window_size,
                 (unsigned) packet_count));
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      SshIkev2Packet *store_p = &transmit_window->packets_head;
      SshIkev2Packet last_packet = NULL;
      SshUInt32 decoded_packets = 0;

      while (status == SSH_IKEV2_ERROR_OK &&
             decoded_packets < packet_count)
        {
          size_t parsed_bytes;

          status =
              ikev2_window_decode_packet(
                      ike_sa,
                      buf + offset,
                      len - offset,
                      &parsed_bytes,
                      store_p);

          if (status == SSH_IKEV2_ERROR_OK)
            {
              offset += parsed_bytes;

              last_packet = *store_p;
              store_p = &last_packet->window_next;

              ++decoded_packets;

              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Transmit window %p: "
                       "Decoding packet %p message_id %u.",
                               transmit_window,
                               last_packet,
                               last_packet->message_id));
            }
        }

      transmit_window->packets_tail = last_packet;
    }

  if (status != SSH_IKEV2_ERROR_OK)
    ikev2_transmit_window_uninit(transmit_window);

  return status;
}


/*
  Initialise a receive window.
 */
void
ikev2_receive_window_init(SshIkev2ReceiveWindow receive_window)
{
  receive_window->window_size = 1;
  receive_window->expected_id = 0;
  receive_window->packets_head = NULL;
  receive_window->packets_tail = NULL;
  SSH_DEBUG(SSH_D_LOWOK, ("Receive window %p initialised", receive_window));
}


/*
  Computes and stores a hash value of the encoded packet into the
  packet structure.

  Check request against current receive window. Return TRUE, denoting
  new request, if packets message_id is within the window and no
  packet with the message_id is stored within the window.

  If a response packet with same message_id and same stored hash value
  is found the response is retransmitted and FALSE is returned.

  If a request packet with same message_id and same stored hash value
  is found, FALSE is returned. This case means that the request is
  being processed already and a response should be sent soon anyway.

  When FALSE is returned the caller should drop the packet without
  further processing.
 */
Boolean
ikev2_receive_window_check_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet)
{
  SshIkev2Packet packet;

  SSH_ASSERT((request_packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0);

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "Checking request packet %p message_id %u.",
                   receive_window,
                   request_packet,
                   request_packet->message_id));

  ikev2_window_packet_hash_compute(request_packet);

  for (packet = receive_window->packets_head;
       packet && packet->message_id != request_packet->message_id;
       packet = packet->window_next)
    ;

  if (packet)
    {
      if (ikev2_window_packet_hash_equal(packet, request_packet))
        {
          /*
            If we have a packet with matching message_id and hash and
            it is not a response, then the request packet is so fast
            restransmit that we are still processing the originally
            received request i.e. the "packet".
           */

          ssh_log_event(SSH_LOGFACILITY_DAEMON,
                        SSH_LOG_INFORMATIONAL,
                        "IKEv2 packet R(%@:%d <- %@:%d): mID=%u",
                        ssh_ipaddr_render, request_packet->server->ip_address,
                        (request_packet->use_natt ?
                         request_packet->server->nat_t_local_port :
                         request_packet->server->normal_local_port),
                        ssh_ipaddr_render, request_packet->remote_ip,
                        request_packet->remote_port,
                        request_packet->message_id);

          if ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)
            {
              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Receive window %p: "
                       "packet %p message_id %u matched packet %p: "
                       "no response ready yet.",
                       receive_window,
                       request_packet,
                       request_packet->message_id,
                       packet));
            }
          else if (packet->sent != 1)
            {
              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Receive window %p: "
                       "packet %p message_id %u matched packet %p: "
                       "response not yet sent.",
                       receive_window,
                       request_packet,
                       request_packet->message_id,
                       packet));
            }
          else
            {
              /* There is a response here already retransmit it */
              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Receive window %p: "
                       "packet %p message_id %u matched response %p: "
                       "retransmitting.",
                       receive_window,
                       request_packet,
                       request_packet->message_id,
                       packet));

              ikev2_udp_retransmit_response_packet(
                      packet,
                      request_packet->server,
                      request_packet->remote_ip,
                      request_packet->remote_port);

              ikev2_debug_packet_out_retransmit(request_packet->ike_sa,
                                                packet);
            }
        }
      else
        {
          SSH_DEBUG(
                  SSH_D_LOWOK,
                  ("Receive window %p: "
                   "packet %p message_id %u matched packet %p: "
                   "packet hash mismatch.",
                           receive_window,
                           request_packet,
                           request_packet->message_id,
                           packet));
        }

      return FALSE;
    }

  if (request_packet->message_id < receive_window->expected_id)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Receive window %p: "
               "packet %p message_id %u out of window: "
               "old retransmit.",
                       receive_window,
                       request_packet,
                       request_packet->message_id));

      return FALSE;
    }

  if (request_packet->message_id >=
      (receive_window->expected_id + receive_window->window_size))
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Receive window %p: "
               "packet %p message_id %u out of window: "
               "future packet.",
                       receive_window,
                       request_packet,
                       request_packet->message_id));

      return FALSE;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "packet %p message_id %u in window: new request.",
                   receive_window,
                   request_packet,
                   request_packet->message_id));

  return TRUE;
}


/*
   Called after the request has been verified as to be an authentic
   request and shall produce a response. This reqistration will cause
   ikev2_receive_window_check_request() to return FALSE for possible
   fast retransmits of the packet thus getting them to be silently
   ignored until a response is inserted.

   As a side-effect the receive window moves and responses left
   outside are removed and freed.

   Returns TRUE if registration was successful.

   Returns FALSE if registration failed. A request with the same
   message_id already in the receive window. This can happen if two
   copies of the same request are received so closely that they both
   get through the ikev2_receive_window_check_request() call.
 */
Boolean
ikev2_receive_window_register_request(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet request_packet)
{
  SshIkev2Packet packet;

  /* check for existing packet with same message_id */
  for (packet = receive_window->packets_head;
       packet && packet->message_id != request_packet->message_id;
       packet = packet->window_next)
    ;

  if (packet)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Receive window %p: "
               "request %p message_id %u resgistration failed: "
               "a %s packet %p exists.",
                       receive_window,
                       request_packet,
                       request_packet->message_id,
                       ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0 ?
                        "response" : "request"),
                       packet));

      return FALSE;
    }


  /* Go through packets and drop response that now fall outside the window */
  if (receive_window->packets_head)
    {
      SshIkev2Packet *remove_p = &receive_window->packets_head;
      SshIkev2Packet tail = NULL;

      packet = *remove_p;
      while (packet)
        {
          if ((packet->message_id + receive_window->window_size) <
              request_packet->message_id)
            {
              *remove_p = packet->window_next;

              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Receive window %p: "
                       "packet %p fell out of window.",
                               receive_window,
                               packet));

              ikev2_window_packet_done(packet);
            }
          else
            {
              tail = packet;
              remove_p = &packet->window_next;
            }

          packet = *remove_p;
        }

      receive_window->packets_tail = tail;
    }


  /* Add the registered request to tail of the window queue */
  if (receive_window->packets_head)
    {
      SSH_ASSERT(receive_window->packets_tail != NULL);

      receive_window->packets_tail->window_next = request_packet;
    }
  else
    {
      receive_window->packets_head = request_packet;
    }

  receive_window->packets_tail = request_packet;
  request_packet->window_next = NULL;

  request_packet->in_window = 1;

  /*
     Find out what is the message id that we are expecting to receive
     next. The search will find either the top or the next "hole" in
     the window.
  */
  packet = receive_window->packets_head;
  while (packet)
    {
      if (packet->message_id == receive_window->expected_id)
        {
          /* We have the expected id start expecting next one */
          ++receive_window->expected_id;

          /* restart search; the packets are not ordered */
          packet = receive_window->packets_head;

          SSH_DEBUG(
                  SSH_D_LOWOK,
                  ("Receive window %p: "
                   "expected id now %u.",
                           receive_window,
                           receive_window->expected_id));
        }
      else
        {
          packet = packet->window_next;
        }
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "request %p registered successfully.",
                   receive_window,
                   request_packet));

  return TRUE;
}



/*
  Replaces an existing registered request from the receive window with
  a response to the request.

  The packet hash from the request packet is copied to the response
  packet structure for comparison with possible retransmissions of the
  request.

  The function expects that there is a registered request packet in
  the receive window.
 */
void
ikev2_receive_window_insert_response(
        SshIkev2ReceiveWindow receive_window,
        SshIkev2Packet response_packet)
{
  SshIkev2Packet packet;
  SshIkev2Packet *replace_p;

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "inserting response %p message_id %u.",
                   receive_window,
                   response_packet,
                   response_packet->message_id));

  SSH_ASSERT(receive_window->packets_head != NULL);

  replace_p = &receive_window->packets_head;
  for (packet = receive_window->packets_head;
       packet->message_id != response_packet->message_id;
       packet = packet->window_next)
    {
      replace_p = &packet->window_next;
    }

  SSH_ASSERT(packet != NULL);

  ikev2_window_packet_hash_copy(response_packet, packet);

  *replace_p = response_packet;
  response_packet->window_next = packet->window_next;
  if (receive_window->packets_tail == packet)
    {
      receive_window->packets_tail = response_packet;
    }

  response_packet->in_window = 1;

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "request packet %p message_id %u done.",
                   receive_window,
                   packet,
                   packet->message_id));

  ikev2_window_packet_done(packet);
}



/*
  Encode receive window to a linear memory buffer.
 */
SshIkev2Error
ikev2_receive_window_encode(
        SshIkev2Sa ike_sa,
        unsigned char **buf,
        size_t *len)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshBufferStruct buffer;
  SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;
  SshIkev2Packet packet;
  SshUInt32 packet_count = 0;
  size_t offset;

  ssh_buffer_init(&buffer);

  for (packet = receive_window->packets_head;
       packet != NULL;
       packet = packet->window_next)
    {
      ++packet_count;
    }

  offset =
      ssh_encode_buffer(
              &buffer,
              SSH_ENCODE_UINT32(receive_window->expected_id),
              SSH_ENCODE_UINT32(receive_window->window_size),
              SSH_ENCODE_UINT32(packet_count),
              SSH_FORMAT_END);

  if (offset == 0)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Receive window %p: "
               "Encode failed: out of memory.",
                       receive_window));

      status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "Encoding: expected_id %u, window_size %u, packets %u.",
                   receive_window,
                   receive_window->expected_id,
                   receive_window->window_size,
                   (unsigned) packet_count));


  for (packet = receive_window->packets_head;
       status == SSH_IKEV2_ERROR_OK &&
           packet != NULL;
       packet = packet->window_next)
    {
      SSH_DEBUG(
              SSH_D_LOWOK,
              ("Receive window %p: "
               "Encoding packet %p message_id %u.",
                       receive_window,
                       packet,
                       packet->message_id));

      status =
          ikev2_window_encode_packet(
                  &buffer,
                  packet);
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      *buf = ssh_buffer_steal(&buffer, len);
    }

  ssh_buffer_uninit(&buffer);

  return status;
}


/*
  Establish a new receive window to given ike_sa decoding its
  contents from given buffer.
 */
SshIkev2Error
ikev2_receive_window_decode(
        SshIkev2Sa ike_sa,
        unsigned char *buf,
        size_t len)
{
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;
  SshIkev2ReceiveWindow receive_window = ike_sa->receive_window;
  SshUInt32 packet_count;
  size_t offset = 0;

  ikev2_receive_window_init(receive_window);

  offset = ssh_decode_array(buf, len,
                            SSH_DECODE_UINT32(&receive_window->expected_id),
                            SSH_DECODE_UINT32(&receive_window->window_size),
                            SSH_DECODE_UINT32(&packet_count),
                            SSH_FORMAT_END);

  if (offset == 0)
    {
      status = SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Receive window %p: "
                 "Decoding: expected_id %u, window_size %u, packets %u.",
                 receive_window,
                 receive_window->expected_id,
                 receive_window->window_size,
                 (unsigned) packet_count));
    }

  if (status == SSH_IKEV2_ERROR_OK)
    {
      SshIkev2Packet *store_p = &receive_window->packets_head;
      SshIkev2Packet last_packet = NULL;
      SshUInt32 decoded_packets = 0;

      while (status == SSH_IKEV2_ERROR_OK &&
             decoded_packets < packet_count)
        {
          size_t parsed_bytes;

          status =
              ikev2_window_decode_packet(
                      ike_sa,
                      buf + offset,
                      len - offset,
                      &parsed_bytes,
                      store_p);

          if (status == SSH_IKEV2_ERROR_OK)
            {
              offset += parsed_bytes;

              last_packet = *store_p;
              store_p = &last_packet->window_next;

              ++decoded_packets;

              SSH_DEBUG(
                      SSH_D_LOWOK,
                      ("Receive window %p: "
                       "Decoding packet %p message_id %u.",
                               receive_window,
                               last_packet,
                               last_packet->message_id));
            }
        }

      receive_window->packets_tail = last_packet;
    }

  if (status != SSH_IKEV2_ERROR_OK)
    ikev2_receive_window_uninit(receive_window);

  return status;
}


/*
  Set new size for receive window.
 */
SshIkev2Error
ikev2_receive_window_set_size(
        SshIkev2ReceiveWindow receive_window,
        unsigned int newsize)
{
  if (newsize > SSH_IKEV2_MAX_WINDOW_SIZE)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Receive window %p: "
               "Denying request to grow window beyond hard limit of %d to %u",
                       receive_window,
                       SSH_IKEV2_MAX_WINDOW_SIZE,
                       newsize));

      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  if (newsize < receive_window->window_size)
    {
      SSH_DEBUG(
              SSH_D_FAIL,
              ("Receive window %p: "
               "Denying request to reduce window from %u to %u.",
                       receive_window,
                       receive_window->window_size,
                       newsize));

      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  if (receive_window->window_size == newsize)
    {
      /* Silently ignore setting to current value. */
      return SSH_IKEV2_ERROR_OK;
    }

  SSH_DEBUG(
          SSH_D_LOWOK,
          ("Receive window %p: "
           "Setting window size from %u to %u.",
                   receive_window,
                   receive_window->window_size,
                   newsize));

  receive_window->window_size = newsize;

  return SSH_IKEV2_ERROR_OK;
}


/*
  Free receive window and it's packets.
 */
void
ikev2_receive_window_uninit(SshIkev2ReceiveWindow receive_window)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Uninitialising receive window %p", receive_window));
  ikev2_window_packet_list_done(receive_window->packets_head);
}


#ifdef SSHDIST_IKE_MOBIKE

/*
  Change server of the packet.
*/
static void
ikev2_window_packet_change_server(
        SshIkev2Packet packet,
        SshIkev2Server server)
{
  if (packet->server != server)
    {
      packet->server = server;
      if (packet->ed)
        {
          packet->ed->multiple_addresses_used = 1;
        }
    }
}


/*
  Change server of all packets in transmit and receive windows of
  given ike_sa.
 */
void
ikev2_window_change_server(
        SshIkev2Sa ike_sa,
        SshIkev2Server server)
{
  SshIkev2Packet packet;

  for (packet = ike_sa->transmit_window->packets_head;
       packet != NULL;
       packet = packet->window_next)
    {
      SSH_DEBUG(
              SSH_D_NICETOKNOW,
              ("Transmit window %p: "
               "Packet %p from server %p to server %p",
                       ike_sa->transmit_window,
                       packet,
                       packet->server,
                       server));

      ikev2_window_packet_change_server(packet, server);
    }

  for (packet = ike_sa->receive_window->packets_head;
       packet != NULL;
       packet = packet->window_next)
    {
      SSH_DEBUG(
              SSH_D_NICETOKNOW,
              ("Receive window %p: "
               "Packet %p from server %p to server %p",
                       ike_sa->receive_window,
                       packet,
                       packet->server,
                       server));

      ikev2_window_packet_change_server(packet, server);
    }
}

#endif /* SSHDIST_IKE_MOBIKE */


/*
  Set retransmit counter of all packet in the transmit window of a
  given ike_sa.
 */
void
ikev2_window_set_retransmit_count(
        SshIkev2Sa ike_sa,
        SshUInt16 retransmit_counter)
{
  SshIkev2Packet packet;

  SSH_DEBUG(
          SSH_D_NICETOKNOW,
          ("Transmit window %p: "
           "Setting retransmit count to %d on IKE SA %p",
                   ike_sa->transmit_window,
                   (int) retransmit_counter,
                   ike_sa));


  for (packet = ike_sa->transmit_window->packets_head;
       packet != NULL;
       packet = packet->window_next)
    {
      if (packet->retransmit_counter < retransmit_counter)
        {
          packet->retransmit_counter = retransmit_counter;
        }
    }
}

/* eof */
