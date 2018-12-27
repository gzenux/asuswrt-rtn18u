/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utilities for IKEv2 MOBIKE.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshencode.h"
#include "sshinetencode.h"

#define SSH_DEBUG_MODULE "SshIkev2MobIKE"

#ifdef SSHDIST_IKE_MOBIKE

void
ikev2_reply_cb_get_additional_addresses(SshIkev2Error error_code,
                                        SshUInt32 num_local_addresses,
                                        SshIpAddr local_address_list,
                                        void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadNotifyStruct notify[1];
  SshIpAddr ip_addr;
  unsigned char buffer[16];
  size_t buffer_len;
  Boolean is_ipv6;
  SshUInt32 i, address_cnt;

  memset(notify, 0, sizeof(*notify));

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  /* Set the sending addresses from the IKE SA if the remote address
     is not defined.  */
  if (!SSH_IP_DEFINED(packet->remote_ip))
    {
      SSH_ASSERT(packet->ike_sa != NULL);
      packet->server = packet->ike_sa->server;
      *packet->remote_ip = *packet->ike_sa->remote_ip;
      packet->remote_port = packet->ike_sa->remote_port;

      if (packet->ike_sa->flags &
          (SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T |
           SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
        packet->use_natt = 1;
      else
        packet->use_natt = 0;
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Currently used address is %@ <-> %@",
                   ssh_ipaddr_render, packet->server->ip_address,
                   ssh_ipaddr_render, packet->remote_ip));

  /* Set the error code if error. */
   if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Get local addresses failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }
   SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Got %d addresses",
                                 (int) num_local_addresses));

   address_cnt = 0;
   for (i = 0; i < num_local_addresses; i++)
    {
      ip_addr = (SshIpAddr)((unsigned char *)local_address_list +
                            i * sizeof(SshIpAddrStruct));
      /* Skip the current address we are using. */
      if (SSH_IP_EQUAL(ip_addr, packet->server->ip_address))
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Skipping N(ADDITIONAL_ADDRESSES) for "
                           "currently used address %@",
                           ssh_ipaddr_render, ip_addr));
          continue;
        }

      is_ipv6 = SSH_IP_IS6(ip_addr) ? TRUE : FALSE;

      SSH_IP_ENCODE(ip_addr, buffer, buffer_len);

      if (is_ipv6)
        notify->notify_message_type = SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS;
      else
        notify->notify_message_type = SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS;

      notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
      notify->spi_size = 0;
      notify->spi_data = NULL;
      notify->notification_size = buffer_len;
      notify->notification_data = buffer;

      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(ADDITIONAL_ADDRESSES) for "
                                       "address %@",
                                       ssh_ipaddr_render, ip_addr));
      if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                              &packet->ed->next_payload_offset) == 0)
        ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      address_cnt++;
    }

   /* Only send the NO_ADDITIONAL_ADDRESSES notificiation for informational
      exchanges. */
   if (packet->ed->state == SSH_IKEV2_STATE_INFORMATIONAL &&
       address_cnt == 0)
     {
       notify->notify_message_type = SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES;
       notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
       notify->spi_size = 0;
       notify->spi_data = NULL;
       notify->notification_size = 0;
       notify->notification_data = NULL;

       /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(NO_ADDITIONAL_ADDRESSES)"));
      if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                              &packet->ed->next_payload_offset) == 0)
        ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
     }
   return;
}


/* Do async operation to request additional addresses
   and add them to the outgoing packet as additional address
   notifications. Moves to the error state in case of error, otherwise
   simply continues thread, and assumes the next state is already
   set. */
void ikev2_add_additional_addresses(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* OK, Added to *mobike_add_additional_addrs, responder_out_mobike. */
  SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_additional_address_list)
    (ike_sa->server->sad_handle, packet->ed,
     ikev2_reply_cb_get_additional_addresses, packet);
}

void ikev2_add_unexpected_nat_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotifyStruct notify[1];

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  memset(notify, 0, sizeof(*notify));

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(UNEXPECTED_NAT_DETECTED)"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
}

void ikev2_info_add_cookie2_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotifyStruct notify[1];
  int i;

  memset(notify, 0, sizeof(*notify));

  /* Add a Cookie 2 notification */
  for (i = 0; i < sizeof(packet->ed->info_ed->cookie2); i++)
    packet->ed->info_ed->cookie2[i] = ssh_random_get_byte();

  packet->ed->info_ed->flags |= SSH_IKEV2_INFO_COOKIE2_ADDED;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_COOKIE2;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = sizeof(packet->ed->info_ed->cookie2);
  notify->notification_data = packet->ed->info_ed->cookie2;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(COOKIE2)"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
}


void ikev2_add_no_nats_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotifyStruct notify[1];
  unsigned char buffer[36];
  Boolean is_ipv6 = SSH_IP_IS6(packet->remote_ip);

  memset(notify, 0, sizeof(*notify));

  /* Note that the NO_NATS notify payload is constructed before the final
     addresses used for sending the packet out are determined. If the
     addresses change because a new address pair is requested from policy, the
     contents of the NO_NATS payload will not match the IP addreses in the
     packet as recevied at the peer. This will cause the peer to reply with
     an UNEXPECTED_NAT_DETECTED notification. This is OK since the exchange
     will finish with 'multiple_addresses_used flag' and so address update
     will be redone. */
  if (is_ipv6)
    {
      SSH_IP6_ENCODE(packet->server->ip_address, buffer);
      SSH_IP6_ENCODE(packet->remote_ip, buffer + 16);
      SSH_PUT_16BIT(buffer + 32,
                    packet->use_natt ? packet->server->nat_t_local_port :
                    packet->server->normal_local_port);
      SSH_PUT_16BIT(buffer + 34, packet->remote_port);

    }
  else
    {
      SSH_IP4_ENCODE(packet->server->ip_address, buffer);
      SSH_IP4_ENCODE(packet->remote_ip, buffer + 4);
      SSH_PUT_16BIT(buffer + 8,
                    packet->use_natt ? packet->server->nat_t_local_port :
                    packet->server->normal_local_port);
      SSH_PUT_16BIT(buffer + 10, packet->remote_port);
    }

  /* First update the next payload pointer of the previous payl oad. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_NO_NATS_ALLOWED;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = is_ipv6 ? 36 : 12;
  notify->notification_data = buffer;

    /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(NO_NATS_ALLOWED)"));

  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);

  if (packet->ed->info_ed)
    packet->ed->info_ed->flags |= SSH_IKEV2_INFO_NO_NATS_ALLOWED_ADDED;

  return;
}

SshIkev2Error ikev2_check_no_nats_notify(SshIkev2Packet packet)
{
  SshIkev2PayloadNotify notify;
  SshIpAddrStruct src_ip, dst_ip;
  SshUInt16 src_port, dst_port;

  notify = packet->ed->notify;

  while (notify != NULL)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_NO_NATS_ALLOWED &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_data != NULL &&
          (notify->notification_size == 12 ||
           notify->notification_size == 36))
        {
          if (notify->notification_size == 12)
            {
              SSH_IP_DECODE(&src_ip, notify->notification_data, 4);
              SSH_IP_DECODE(&dst_ip, notify->notification_data + 4, 4);
              src_port = SSH_GET_16BIT(notify->notification_data + 8);
              dst_port = SSH_GET_16BIT(notify->notification_data + 10);
            }
          else
            {
              SSH_IP_DECODE(&src_ip, notify->notification_data, 16);
              SSH_IP_DECODE(&dst_ip, notify->notification_data + 16, 16);
              src_port = SSH_GET_16BIT(notify->notification_data + 32);
              dst_port = SSH_GET_16BIT(notify->notification_data + 34);
            }

          /* Check the notify payload agress with the IP addresses and ports
             present in the packet */
          if (SSH_IP_CMP(&dst_ip, packet->server->ip_address) ||
              SSH_IP_CMP(&src_ip, packet->remote_ip) ||
              (dst_port != (packet->use_natt ?
               packet->server->nat_t_local_port :
               packet->server->normal_local_port)) ||
              src_port != packet->remote_port)
            {
              SSH_IKEV2_DEBUG(SSH_D_FAIL,
                          ("NO_NATS payload local=%@:%d, remote=%@:%d,"
                           "do not match those in packet "
                           "%@:%d, %@:%d",
                           ssh_ipaddr_render, &dst_ip, dst_port,
                           ssh_ipaddr_render, &src_ip, src_port,
                           ssh_ipaddr_render,
                           packet->server->ip_address,
                           packet->use_natt ?
                           packet->server->nat_t_local_port :
                           packet->server->normal_local_port,
                           ssh_ipaddr_render,  packet->remote_ip,
                           packet->remote_port));
              return SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED;
            }
          else
            {
              return SSH_IKEV2_ERROR_OK;
            }
        }
      notify = notify->next_notify;
    }
  return SSH_IKEV2_ERROR_OK;
}

SshIkev2Error
ikev2_mobike_encode(SshIkev2Sa sa, unsigned char **buf, size_t *len)
{
  size_t offset;
  int i;
  SshBufferStruct buffer;

  SSH_ASSERT(sa != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(len != NULL);

  ssh_buffer_init(&buffer);

  offset =
    ssh_encode_buffer(&buffer,
                      SSH_ENCODE_UINT32(sa->max_update_address_mid),
                      SSH_ENCODE_UINT32(sa->max_additional_address_mid),
                      SSH_ENCODE_UINT32(sa->num_additional_ip_addresses),
                      SSH_FORMAT_END);
  if (offset != 12)
    goto error;

  for (i = 0; i < sa->num_additional_ip_addresses; i++)
    {
      offset =
        ssh_encode_buffer(&buffer,
                          SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                             &sa->additional_ip_addresses[i]),
                          SSH_FORMAT_END);
      if (offset == 0)
        goto error;
    }

  *buf = ssh_buffer_steal(&buffer, len);
  ssh_buffer_uninit(&buffer);

  return SSH_IKEV2_ERROR_OK;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Encoding of IKE SA MOBIKE parameters failed"));
  ssh_buffer_uninit(&buffer);
  *len = 0;
  return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
}

SshIkev2Error
ikev2_mobike_decode(SshIkev2Sa sa, unsigned char *buf, size_t len)
{
  size_t total_len, offset;
  int i;

  SSH_ASSERT(sa != NULL);
  SSH_ASSERT(buf != NULL);

  offset =
    ssh_decode_array(buf, len,
                     SSH_DECODE_UINT32(&sa->max_update_address_mid),
                     SSH_DECODE_UINT32(&sa->max_additional_address_mid),
                     SSH_DECODE_UINT32(&sa->num_additional_ip_addresses),
                     SSH_FORMAT_END);
  if (offset != 12)
    goto error;
  total_len = offset;

  for (i = 0; i < sa->num_additional_ip_addresses; i++)
    {
      offset =
        ssh_encode_array(buf + total_len, len - total_len,
                         SSH_DECODE_SPECIAL_NOALLOC(
                         ssh_decode_ipaddr_array,
                         &sa->additional_ip_addresses[i]),
                         SSH_FORMAT_END);
      if (offset == 0)
        goto error;
      total_len += offset;
    }

  if (len != total_len)
    goto error;

  return SSH_IKEV2_ERROR_OK;

 error:
  return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
}

#endif /* SSHDIST_IKE_MOBIKE */
