/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for requesting cookie
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateRequestCookieOut"

/* Send cookie request out. */
SSH_FSM_STEP(ikev2_state_request_cookie_out)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
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
  notify->notify_message_type = SSH_IKEV2_NOTIFY_COOKIE;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = packet->ed->ike_ed->cookie_len;
  notify->notification_data = packet->ed->ike_ed->cookie;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(COOKIE) request"));
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

