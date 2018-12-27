/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for sending INVALID_KE_PAYLOAD.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateKeErrorOut"

/* Send invalid KE error out. */
SSH_FSM_STEP(ikev2_state_ke_error_out)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
  unsigned char temp_buffer[2];
  SshIkev2Error err;
  SshBuffer buffer;
  size_t len;

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  notify->protocol = 0;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 2;
  notify->notification_data = temp_buffer;
  SSH_PUT_16BIT(temp_buffer, packet->ed->ike_ed->
                ike_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(INVALID_KE_PAYLOAD) request"));
  len = ikev2_encode_notify(packet, buffer, notify, NULL);
  if (len == 0)
    {
      ssh_buffer_free(buffer);
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NOTIFY;

  /* Zero out responder SPI.*/
  memset(packet->ike_spi_r, 0, 8);

  err = ikev2_encode_header(packet, buffer);
  ssh_buffer_free(buffer);
  SSH_FSM_SET_NEXT(ikev2_state_send_and_destroy);
  return ikev2_error(packet, err);
}

/* Send invalid KE error out. */
SSH_FSM_STEP(ikev2_state_reply_ke_error_out)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
  unsigned char temp_buffer[2];
  SshIkev2Error err;
  SshBuffer buffer;
  SshUInt16 group;
  size_t len;

  SSH_FSM_SET_NEXT(ikev2_state_send);

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  notify->protocol = 0;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 2;
  notify->notification_data = temp_buffer;
  group = 0;
  if (packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H] != NULL)
    group = packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id;

  SSH_PUT_16BIT(temp_buffer, group);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(INVALID_KE_PAYLOAD) request"));
  len = ikev2_encode_notify(packet, buffer, notify, NULL);
  if (len == 0)
    {
      ssh_buffer_free(buffer);
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NOTIFY;

  err = ikev2_encrypt_packet(packet, buffer);
  ssh_buffer_free(buffer);

  /* Then we destroy the exchange */
  ikev2_free_exchange_data(packet->ed->ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}
