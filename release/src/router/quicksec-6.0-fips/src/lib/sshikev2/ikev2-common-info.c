/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine common INFORMATIONAL exchange functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInfoUtils"

 /* Add delete payloads to informational exchange. */
void ikev2_info_add_delete(SshIkev2Packet packet)
{
  SshIkev2PayloadDelete del;

  del = packet->ed->info_ed->del;
  while (del != NULL)
    {
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_DELETE);

      /* Encode delete payload and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding D"));
      if (ikev2_encode_delete(packet, packet->ed->buffer, del,
                              &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
      del = del->next_delete;
    }
  return;
}

/* Add notify payloads to informational exchange. */
void ikev2_info_add_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotify notify;

  notify = packet->ed->info_ed->notify;
  while (notify != NULL)
    {
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

      /* Encode notify payload and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N"));
      if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                              &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
      notify = notify->next_notify;
    }
  return;
}

/* Add conf payloads to informational exchange. */
void ikev2_info_add_conf(SshIkev2Packet packet)
{
  if (packet->ed->info_ed->conf)
    {
      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_CONF);

      /* Encode conf payload and add it. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding CONF"));
      if (ikev2_encode_conf(packet, packet->ed->buffer,
                            packet->ed->info_ed->conf,
                            &packet->ed->next_payload_offset) == 0)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
    }
  return;
}


