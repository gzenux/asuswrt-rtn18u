/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#include "sshape_mark.h"

#define SSH_DEBUG_MODULE "SshIkev2PacketDebug"

#define IKEV2_PACKET_MAX_PAYLOADS 50

void
ikev2_add_payload_description_to_buffer(SshIkev2PayloadType type,
                                        SshBuffer buffer)
{
  char *name;

  name = (char *) ssh_ikev2_packet_payload_to_string(type);

  ssh_buffer_append_cstrs(buffer, ", ", NULL);
  ssh_buffer_append_cstrs(buffer, name, NULL);
}

void
ikev2_add_notify_payload_description_to_buffer(SshIkev2NotifyMessageType type,
                                               SshBuffer buffer)
{
  char *name;

  name = (char *) ssh_ikev2_notify_payload_to_string(type);

  ssh_buffer_append_cstrs(buffer, ", ", NULL);
  ssh_buffer_append_cstrs(buffer, name, NULL);
}

#define IKEV2_PACKET_MAX_PAYLOADS 50
#define NEXT_PAYLOAD_HEADER_IN_IKEV2_HEADER 16
#define IKEV2_HEADER_LEN 28

/* Below is needed to print out packet description as in RFCs */
void ikev2_list_packet_payloads(SshIkev2Packet packet,
                                unsigned char *buffer,
                                size_t buffer_len,
                                SshIkev2PayloadType first_payload,
                                Boolean is_sending)
{
  SshIkev2PayloadType payloads[IKEV2_PACKET_MAX_PAYLOADS],
    next_payload, curr_payload;
  SshIkev2NotifyMessageType notify_messages[IKEV2_PACKET_MAX_PAYLOADS];
  SshUInt32 payload_index = 0, payload_len;
  unsigned char null = 0x00;    /* End the string */
  SshUInt32 i;
  SshBuffer payload_description;

  memset(payloads, 0, sizeof(payloads));
  memset(notify_messages, 0, sizeof(notify_messages));

  curr_payload = first_payload;
  i = 0;

  for (payload_index = 0;
       payload_index < IKEV2_PACKET_MAX_PAYLOADS;
       payload_index++)
    {
      if (curr_payload == SSH_IKEV2_PAYLOAD_TYPE_NONE)
        break;

      if (i + 8 > buffer_len)
        {
          if ((curr_payload == SSH_IKEV2_PAYLOAD_TYPE_NOTIFY) ||
              (i + 4 > buffer_len))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("IKEv2 payload headers are corrupted, unable to list "
                         "payloads"));
              return;
            }
        }


      next_payload = SSH_GET_8BIT(&buffer[i]);

      payload_len = SSH_GET_16BIT(&buffer[i + 2]);

      if (curr_payload == SSH_IKEV2_PAYLOAD_TYPE_NOTIFY)
        {
          notify_messages[payload_index] =
            SSH_GET_16BIT(&buffer[i + 6]);
          payload_index++;
        }
      else
        {
          payloads[payload_index] = curr_payload;
          payload_index++;
        }

      curr_payload = next_payload;
      i += payload_len;

      SSH_ASSERT(i < SSH_IKEV2_MAX_PAYLOAD_SIZE * IKEV2_PACKET_MAX_PAYLOADS);
    }

  /* Output the packet */
  payload_description = ssh_buffer_allocate();

  if (payload_description == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to output received IKE-packet"));
      return;
    }

  ssh_buffer_clear(payload_description);

  ssh_buffer_append_cstrs(payload_description, "HDR", NULL);

  for (i = 0; i < payload_index; i++)
    {
      if (payloads[i] != 0)
        ikev2_add_payload_description_to_buffer(payloads[i],
                                                payload_description);
      else if (notify_messages[i] != 0)
        ikev2_add_notify_payload_description_to_buffer(notify_messages[i],
                                                       payload_description);
      else
        continue;
    }

  ssh_buffer_append(payload_description, &null, 1);

  SSH_DEBUG(SSH_D_HIGHOK, ("%s packet: %s",
                           is_sending ? "Sending" : "Receiving",
                           ssh_buffer_ptr(payload_description)));

  SSH_APE_MARK(1, ("%s packet(m-id=%d): %s",
                   is_sending ? "Sending" : "Receiving",
                   packet->message_id, ssh_buffer_ptr(payload_description)));

  if (is_sending)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_INFORMATIONAL,
                    "IKEv2 packet S(%@:%d -> %@:%d): mID=%u, %s",
                    ssh_ipaddr_render, packet->server->ip_address,
                    packet->use_natt ?
                    packet->server->nat_t_local_port :
                    packet->server->normal_local_port,
                    ssh_ipaddr_render, packet->remote_ip,
                    packet->remote_port,
                    packet->message_id,
                    ssh_buffer_ptr(payload_description));
    }
  else
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON,
                    SSH_LOG_INFORMATIONAL,
                    "IKEv2 packet R(%@:%d <- %@:%d): mID=%u, %s",
                    ssh_ipaddr_render, packet->server->ip_address,
                    packet->use_natt ?
                    packet->server->nat_t_local_port :
                    packet->server->normal_local_port,
                    ssh_ipaddr_render, packet->remote_ip,
                    packet->remote_port,
                    packet->message_id,
                    ssh_buffer_ptr(payload_description));
    }

  ssh_buffer_free(payload_description);
}
