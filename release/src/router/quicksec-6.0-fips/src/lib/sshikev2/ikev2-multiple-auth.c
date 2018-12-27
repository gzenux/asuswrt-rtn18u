/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utilities for RFC 4739, Multiple Auth Exchanges in IKEv2.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2Multiauth"

#ifdef SSH_IKEV2_MULTIPLE_AUTH

/* Check for the MULTIPLE_AUTH_SUPPORTED notify*/

Boolean ikev2_check_multiple_auth(SshIkev2Packet packet)
{
  SshIkev2PayloadNotify notify;
  int i;

  for(i = 0, notify = packet->ed->notify;
      i < packet->ed->notify_count && notify != NULL;
      i++, notify = notify->next_notify)
    {
      if (notify->notify_message_type ==
          SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size == 0)
        {
          /* Responder supports IKEv2 multiple authenticatiosn */
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("N(MULTIPLE_AUTH_SUPPORTED) "
                                           "found"));
          return TRUE;
        }
    }

  return FALSE;
}


void ikev2_add_multiple_auth_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotifyStruct notify[1];

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  memset(notify, 0, sizeof(*notify));

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(MULTIPLE_AUTH_SUPPORTED)"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
}

void ikev2_add_another_auth_follows(SshIkev2Packet packet)
{
  SshIkev2PayloadNotifyStruct notify[1];

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  memset(notify, 0, sizeof(*notify));

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
}

#endif /* SSH_IKEV2_MULTIPLE_AUTH */
