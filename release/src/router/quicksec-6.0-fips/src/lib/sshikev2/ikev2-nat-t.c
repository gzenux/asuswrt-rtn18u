/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 NAT-T common functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateNatT"

SshUInt16 ikev2_resolve_nat_detection_local_port(SshIkev2Packet packet)
{
  SshUInt16 local_port;

  /* Resolve local port. */
  if (packet->server->forced_nat_t_enabled == TRUE)
    local_port = 0;
  else if (packet->use_natt)
    local_port = packet->server->nat_t_local_port;
  else
    local_port = packet->server->normal_local_port;

  return local_port;
}

/* Calculate hash used in the NAT_DETECTION_*_IP
   notifications. */
SshIkev2Error ikev2_calc_nat_detection(SshIpAddr ip,
                                       SshUInt16 port,
                                       const unsigned char *spi_i,
                                       const unsigned char *spi_r,
                                       unsigned char *digest,
                                       size_t *out_len)
{
  unsigned char buffer[2];
  SshCryptoStatus status;
  SshHash hash;

  *out_len = ssh_hash_digest_length("sha1");
  if (spi_r == NULL)
    spi_r = ssh_custr("\0\0\0\0\0\0\0\0");

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Calculating NAT hash, ip = %@, port = %d, "
             "spi_i = %08lx%08lx, spi_r = %08lx%08lx",
             ssh_ipaddr_render, ip, (int) port,
             (unsigned long)
             SSH_GET_32BIT(spi_i),
             (unsigned long)
             SSH_GET_32BIT(spi_i + 4),
             (unsigned long)
             SSH_GET_32BIT(spi_r),
             (unsigned long)
             SSH_GET_32BIT(spi_r + 4)));

  /* Allocate mac. */
  status = ssh_hash_allocate("sha1", &hash);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: hash allocate failed: %s",
                              ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  ssh_hash_reset(hash);
  ssh_hash_update(hash, spi_i, 8);
  ssh_hash_update(hash, spi_r, 8);
  ssh_hash_update(hash, SSH_IP_ADDR_DATA(ip), SSH_IP_ADDR_LEN(ip));
  SSH_PUT_16BIT(buffer, port);
  ssh_hash_update(hash, buffer, 2);
  status = ssh_hash_final(hash, digest);
  ssh_hash_free(hash);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Error: hash final failed: %s",
                              ssh_crypto_status_message(status)));
      return SSH_IKEV2_ERROR_CRYPTO_FAIL;
    }

  SSH_DEBUG(SSH_D_LOWSTART,
            ("NAT hash = %08lx %08lx %08lx %08lx %08lx",
             (unsigned long)
             SSH_GET_32BIT(digest),
             (unsigned long)
             SSH_GET_32BIT(digest + 4),
             (unsigned long)
             SSH_GET_32BIT(digest + 8),
             (unsigned long)
             SSH_GET_32BIT(digest + 12),
             (unsigned long)
             SSH_GET_32BIT(digest + 16)));
  return SSH_IKEV2_ERROR_OK;
}

/* Add NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP
   notifications to the exchnage. */
void ikev2_add_nat_discovery_notify(SshIkev2Packet packet)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshIkev2PayloadNotifyStruct notify[1];
  size_t hash_len;
  SshIkev2Error error;
  SshUInt16 local_port;

  /* Resolve local port. */
  local_port = ikev2_resolve_nat_detection_local_port(packet);

  /* Fill in the notify payload. */
  error = ikev2_calc_nat_detection(packet->server->ip_address, local_port,
                                   packet->ike_spi_i, packet->ike_spi_r,
                                   digest, &hash_len);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ikev2_error(packet, error);
      return;
    }

  notify->protocol = 0;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = hash_len;
  notify->notification_data = digest;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  /* Encode notify payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    {
      /* Note, that we do not yet continue the thread, as
         there will be more calls to this function, but we
         have already set the state to be error state. */
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  /* Fill in the notify payload. */
  error = ikev2_calc_nat_detection(packet->remote_ip, packet->remote_port,
                                   packet->ike_spi_i, packet->ike_spi_r,
                                   digest, &hash_len);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ikev2_error(packet, error);
      return;
    }

  notify->protocol = 0;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = hash_len;
  notify->notification_data = digest;
  notify->notify_message_type = SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  /* Encode notify payload and add it. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    {
      /* Note, that we do not yet continue the thread, as
         there will be more calls to this function, but we
         have already set the state to be error state. */
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return;
    }

  if (packet->ed->info_ed)
    packet->ed->info_ed->flags |= SSH_IKEV2_INFO_NAT_D_ADDED;

  return;
}

/* Check for the NAT_DETECTION_*_IP notifies. If both NAT detection source
   and destination notifies are present, this sets *nat_t_enabled to TRUE,
   otherwise *nat_t_enabled is set to TRUE.

   If the SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP payload is present and
   does not match the remote IP and port of the packet, this sets *nat_source
   to TRUE, otherwise is set to FALSE.

   If SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP payload is present and
   does not match the local IP and port of the packet, this sets
   *nat_destination to TRUE, otherwise is set to FALSE.

   Returns FALSE in case of error and TRUE otherwise. */
Boolean ikev2_compute_nat_detection(SshIkev2Packet packet,
                                    Boolean use_responder_cookie,
                                    Boolean *nat_t_enabled,
                                    Boolean *nat_source,
                                    Boolean *nat_destination)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  Boolean nat_source_seen, nat_destination_seen;
  SshIkev2PayloadNotify notify;
  size_t hash_len;
  SshIkev2Error error;
  SshUInt16 local_port;

  *nat_t_enabled = TRUE;
  *nat_source = TRUE;
  *nat_destination = TRUE;

  nat_source_seen = FALSE;
  nat_destination_seen = FALSE;

  /* Do we have NAT-T notifies there, and if so are we or
     the other end behind NAT. */
  notify = packet->ed->notify;
  while (notify != NULL)
    {
      if (notify->notify_message_type ==
          SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL)
        {
          nat_source_seen = TRUE;
          error = ikev2_calc_nat_detection(packet->remote_ip,
                                           packet->remote_port,
                                           packet->ike_spi_i,
                                           use_responder_cookie ?
                                           packet->ike_spi_r : NULL,
                                           digest, &hash_len);
          if (error != SSH_IKEV2_ERROR_OK)
            {
              ikev2_error(packet, error);
              return FALSE;
            }
          if (notify->notification_size == hash_len &&
              memcmp(notify->notification_data, digest, hash_len) == 0)
            {
              /* Remote end is not behind NAT. */
              SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Remote end is not behind NAT"));
              *nat_source = FALSE;
            }
        }
      if (notify->notify_message_type ==
          SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL)
        {
          /* Resolve local port. */
          local_port = ikev2_resolve_nat_detection_local_port(packet);

          nat_destination_seen = TRUE;
          error = ikev2_calc_nat_detection(packet->server->ip_address,
                                           local_port,
                                           packet->ike_spi_i,
                                           use_responder_cookie ?
                                           packet->ike_spi_r : NULL,
                                           digest, &hash_len);
          if (error != SSH_IKEV2_ERROR_OK)
            {
              ikev2_error(packet, error);
              return FALSE;
            }
          if (notify->notification_size == hash_len &&
              memcmp(notify->notification_data, digest, hash_len) == 0)
            {
              /* Remote end is not behind NAT. */
              SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("We are not behind NAT"));
              *nat_destination = FALSE;
            }
        }
      notify = notify->next_notify;
    }

  if (nat_source_seen && nat_destination_seen)
    {
      if (*nat_source)
        SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Remote end is behind NAT"));

      if (*nat_destination)
        SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("We are behind NAT"));

   }
  else if (nat_source_seen || nat_destination_seen)
    {
      *nat_t_enabled = FALSE;
      *nat_source = FALSE;
      *nat_destination = FALSE;
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Only one of the NAT_DETECTION payloads seen"));
    }
  else
    {
      *nat_t_enabled = FALSE;
      *nat_source = FALSE;
      *nat_destination = FALSE;
      SSH_IKEV2_DEBUG(SSH_D_UNCOMMON, ("Other end does not support NAT-T"));
    }

  return TRUE;
}

/* Check for the NAT_DETECTION_*_IP notifies and set the
   flags on the ike_sa based on those. */
void ikev2_check_nat_detection(SshIkev2Packet packet,
                               Boolean use_responder_cookie)
{
  Boolean nat_t_enabled, nat_source, nat_destination;

  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("NAT-T is disabled for this IKE SA"));
      return;
    }

  if (!ikev2_compute_nat_detection(packet, use_responder_cookie,
                                   &nat_t_enabled,
                                   &nat_source,
                                   &nat_destination))
    return;

  if (!nat_t_enabled)
    {
      packet->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED;
      SSH_IKEV2_DEBUG(SSH_D_UNCOMMON, ("Other end does not support NAT-T"));
    }
  else
    {
      if (nat_source)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Remote end is behind NAT"));
          packet->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT;
        }
      if (nat_destination)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("We are behind NAT"));
          packet->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT;
        }
    }

  return;
}

/** Check transport mode NAT-T traffic selectors. This that both traffic
    selectors contain only items with one IP address. On success this
    returns TRUE and the caller may safely call
    ikev2_transport_mode_natt_ts_substitute() to perform actual transport
    mode NAT-T traffic selector IP address substitution. */
Boolean
ikev2_transport_mode_natt_ts_check(SshIkev2ExchangeData ed)
{
  SshIpAddrStruct ip;
  int i;

  SSH_ASSERT(ed->ike_sa != NULL);
  SSH_ASSERT(ed->ipsec_ed != NULL);
  SSH_ASSERT(ed->ipsec_ed->ts_i != NULL);
  SSH_ASSERT(ed->ipsec_ed->ts_r != NULL);

  /* Sanity check traffic selectors. */
  if (ed->ipsec_ed->ts_i->number_of_items_used == 0
      || ed->ipsec_ed->ts_r->number_of_items_used == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error: Invalid traffic selectors"));
      return FALSE;
    }

  /* Verify that ts_i does not contain IP ranges and that the items all
     specify the same IP address. */
  ip = *ed->ipsec_ed->ts_i->items[0].start_address;
  for (i = 0; i < ed->ipsec_ed->ts_i->number_of_items_used; i++)
    {
      if (!SSH_IP_EQUAL(ed->ipsec_ed->ts_i->items[i].start_address,
                        ed->ipsec_ed->ts_i->items[i].end_address)
          || !SSH_IP_EQUAL(ed->ipsec_ed->ts_i->items[i].start_address, &ip))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Invalid transport mode NAT-T TS_i %@",
                     ssh_ikev2_ts_render, ed->ipsec_ed->ts_i));
          return FALSE;
        }
    }

  ip = *ed->ipsec_ed->ts_r->items[0].start_address;
  for (i = 0; i < ed->ipsec_ed->ts_r->number_of_items_used; i++)
    {
      if (!SSH_IP_EQUAL(ed->ipsec_ed->ts_r->items[i].start_address,
                        ed->ipsec_ed->ts_r->items[i].end_address)
          || !SSH_IP_EQUAL(ed->ipsec_ed->ts_r->items[i].start_address, &ip))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Invalid transport mode NAT-T TS_r %@",
                     ssh_ikev2_ts_render, ed->ipsec_ed->ts_r));
          return FALSE;
        }
    }

  return TRUE;
}

/** Perform transport mode NAT-T traffic selector IP address substitution
    as specified in RFC5996 2.23.1. This also stores the NAT-T original
    IP addresses for the ends that are detected to be behind NAT. */
void
ikev2_transport_mode_natt_ts_substitute(SshIkev2ExchangeData ed,
                                        SshIkev2PayloadTS ts_local,
                                        SshIkev2PayloadTS ts_remote)
{
  int i;

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
    {
      ed->ipsec_ed->natt_oa_l = *ts_local->items[0].start_address;
      for (i = 0; i < ts_local->number_of_items_used; i++)
        {
          *ts_local->items[i].start_address = *ed->ike_sa->server->ip_address;
          *ts_local->items[i].end_address = *ed->ike_sa->server->ip_address;
        }
    }

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    {
      ed->ipsec_ed->natt_oa_r = *ts_remote->items[0].start_address;
      for (i = 0; i < ts_remote->number_of_items_used; i++)
        {
          *ts_remote->items[i].start_address = *ed->ike_sa->remote_ip;
          *ts_remote->items[i].end_address = *ed->ike_sa->remote_ip;
        }
    }
}


/** Fetch NAT-T original addresses for exchange. This sets or undefines
    'natt_oa_l' and 'natt_oa_r' depending on which IKE peer was behind NAT.
    If no NAT was detected between the peers, then this undefines both. */
void
ssh_ikev2_ipsec_get_natt_oa(SshIkev2ExchangeData ed,
                            SshIpAddr natt_oa_l,
                            SshIpAddr natt_oa_r)
{
  SSH_ASSERT(natt_oa_l != NULL);
  SSH_ASSERT(natt_oa_r != NULL);

  if (ed == NULL || ed->ipsec_ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error: Invalid arguments: ed %p ipsec_ed %p",
                             ed, (ed != NULL ? ed->ipsec_ed : NULL)));
      SSH_IP_UNDEFINE(natt_oa_l);
      SSH_IP_UNDEFINE(natt_oa_r);
      return;
    }

  if ((ed->ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT
                            | SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
      == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Neither end is behind NAT"));
      SSH_IP_UNDEFINE(natt_oa_l);
      SSH_IP_UNDEFINE(natt_oa_r);
      return;
    }

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
    {
      *natt_oa_l = ed->ipsec_ed->natt_oa_l;
      SSH_DEBUG(SSH_D_LOWOK, ("Local end behind NAT, natt_oa_l %@",
                              ssh_ipaddr_render, natt_oa_l));
    }
  else
    SSH_IP_UNDEFINE(natt_oa_l);

  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    {
      *natt_oa_r = ed->ipsec_ed->natt_oa_r;
      SSH_DEBUG(SSH_D_LOWOK, ("Remote end behind NAT, natt_oa_r %@",
                              ssh_ipaddr_render, natt_oa_r));
    }
  else
    SSH_IP_UNDEFINE(natt_oa_r);
}
