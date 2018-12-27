/**
   @copyright
   Copyright (c) 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"

#define SSH_DEBUG_MODULE "SshIkev1PacketDebug"


void
ikev1_add_payload_description_to_buffer(SshIkePayloadType type,
                                        SshBuffer buffer)
{
  char *name;

  name = (char *) ssh_ikev1_packet_payload_to_string(type);

  ssh_buffer_append_cstrs(buffer, ", ", NULL);
  ssh_buffer_append_cstrs(buffer, name, NULL);
}

void
ikev1_add_notify_payload_description_to_buffer(SshIkeNotifyMessageType type,
                                               SshBuffer buffer)
{
  char *name;

  name = (char *) ssh_ikev1_notify_payload_to_string(type);

  ssh_buffer_append_cstrs(buffer, ", ", NULL);
  ssh_buffer_append_cstrs(buffer, name, NULL);
}

/* Below is needed to print out packet description as in RFCs */
void ikev1_list_packet_payloads(SshIkePacket packet,
                                SshIkePayload* payloads,
                                unsigned char* local_ip,
                                SshUInt16 local_port,
                                unsigned char* remote_ip,
                                SshUInt16 remote_port,
                                Boolean is_sending)
{
  SshBuffer payload_description;
  unsigned char null = 0x00;    /* End the string */
  SshUInt32 i;

  payload_description = ssh_buffer_allocate();
  ssh_buffer_clear(payload_description);

  ssh_buffer_append_cstrs(payload_description, "HDR", NULL);

  for (i = 0; i < packet->number_of_payload_packets; i++)
    {
      if (payloads[i]->type == SSH_IKE_PAYLOAD_TYPE_N)
        ikev1_add_notify_payload_description_to_buffer(
            payloads[i]->pl.n.notify_message_type,
            payload_description);
      else
        ikev1_add_payload_description_to_buffer(payloads[i]->type,
                                                payload_description);
    }

  ssh_buffer_append(payload_description, &null, 1);

  if (is_sending)
  {
    ssh_log_event(SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "IKEv1 packet S(%s:%d -> %s:%d): mID=%08lx, %s",
                local_ip, local_port,
                remote_ip,
                remote_port,
                (unsigned long) packet->message_id,
                ssh_buffer_ptr(payload_description));
  }
  else {
    ssh_log_event(SSH_LOGFACILITY_DAEMON,
                SSH_LOG_INFORMATIONAL,
                "IKEv1 packet R(%s:%d <- %s:%d): mID=%08lx, %s",
                local_ip, local_port,
                remote_ip,
                remote_port,
                (unsigned long) packet->message_id,
                ssh_buffer_ptr(payload_description));

  }
  ssh_buffer_free(payload_description);
}
