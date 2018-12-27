/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Payload Encode routines.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIkev2Encode"

/* Helper function to update len at `len_pos' of the buffer.
   Return the length of 0 in case of error. */
size_t ikev2_update_len(SshBuffer buffer, size_t len_pos, size_t len);


/* Each of these functions will get the payload structure,
   and the buffer where the payload is stored. These
   functions only add the payload contents, the generic
   payload header is not added by these functions. These
   functions returns the size used from the buffer, just
   like ssh_encode_buffer functions, or zero if error
   occurred. If the `next_payload_offset' is not NULL then
   the offset of the next_payload in the `buffer' is stored
   there, so the next payload type can later be updated
   using ikev2_update_next_payload. */

/* Encode SA payload. */
size_t ikev2_encode_sa(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadSA sa,
                       int *next_payload_offset)
{
  size_t len, ret, prop_len, spi_len, len_pos;
  unsigned char spi_buffer[4];
  unsigned char *spi;
  int prop, trans;

  SSH_IKEV2_DEBUG_ENCODE(packet, "%.1@", ssh_ikev2_payload_sa_render, sa);

  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  ret = ssh_encode_buffer(buffer,
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_UINT16((SshUInt16) 0),
                          SSH_FORMAT_END);
  if (ret == 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
      return 0;
    }
  len_pos = ssh_buffer_len(buffer) - 2;

  len = 0;

  for(prop = 0; prop < SSH_IKEV2_SA_MAX_PROPOSALS; prop++)
    {
      if (sa->protocol_id[prop] == 0)
        continue;
      if (sa->protocol_id[prop] == SSH_IKEV2_PROTOCOL_ID_IKE)
        {
          if (packet->ed != NULL &&
              packet->ed->ipsec_ed != NULL &&
              packet->ed->ipsec_ed->new_ike_sa != NULL)
            {
              spi_len = 8;
              spi = sa->spis.ike_spi;
              SSH_DEBUG(SSH_D_PCKDMP,
                        ("IKE SPI = %08lx %08lx",
                         SSH_GET_32BIT(spi), SSH_GET_32BIT(spi + 4)));
            }
          else
            {
              spi = NULL;
              spi_len = 0;
              SSH_DEBUG(SSH_D_PCKDMP, ("No IKE SPI"));
            }

        }
      else
        {
          /* We always have only one proposal when initiating, so we use the
             one SPI stored in the ipsec_ed. */
          /* NOTE: if we want to implement multiple proposal support when
             sending proposals, this needs to be modified, or we need to make
             sure that both proposals accept same SPI. */
          spi_len = 4;

          if (packet->ed == NULL)
            return 0;

          if (packet->ed->ipsec_ed == NULL)
            return 0;

          SSH_PUT_32BIT(spi_buffer, packet->ed->ipsec_ed->spi_inbound);
          spi = spi_buffer;
          SSH_DEBUG(SSH_D_PCKDMP, ("IPsec SPI = 0x%08lx",
                                   packet->ed->ipsec_ed->spi_inbound));
        }
      prop_len = 8 + spi_len + sa->number_of_transforms[prop] * 8;
      for(trans = 0; trans < sa->number_of_transforms[prop]; trans++)
        {
          if (sa->proposals[prop][trans].transform_attribute)
            prop_len += 4;
        }
      ret = ssh_encode_buffer(buffer,
                              SSH_ENCODE_CHAR(
                              (unsigned int)
                              ((prop == SSH_IKEV2_SA_MAX_PROPOSALS - 1 ||
                                sa->protocol_id[prop + 1] == 0) ? 0 : 2)),
                              SSH_ENCODE_CHAR((unsigned int) 0),
                              SSH_ENCODE_UINT16((SshUInt16) prop_len),
                              SSH_ENCODE_CHAR(
                              (unsigned int) (sa->proposal_number != 0 ?
                                              sa->proposal_number : prop + 1)),
                              SSH_ENCODE_CHAR(
                              (unsigned int) sa->protocol_id[prop]),
                              SSH_ENCODE_CHAR((unsigned int) spi_len),
                              SSH_ENCODE_CHAR(
                              (unsigned int) sa->number_of_transforms[prop]),
                              SSH_ENCODE_DATA(spi, spi_len),
                              SSH_FORMAT_END);
      if (ret == 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
          return 0;
        }

      len += ret;

      for(trans = 0; trans < sa->number_of_transforms[prop]; trans++)
        {
          ret = ssh_encode_buffer(buffer,
                                  SSH_ENCODE_CHAR(
                                  (unsigned int)
                                  ((trans ==
                                    sa->number_of_transforms[prop] - 1)
                                   ? 0 : 3)),
                                  SSH_ENCODE_CHAR((unsigned int) 0),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  ((sa->proposals[prop][trans].
                                    transform_attribute) ? 12 : 8)),
                                  SSH_ENCODE_CHAR(
                                  (unsigned int)
                                  sa->proposals[prop][trans].type),
                                  SSH_ENCODE_CHAR((unsigned int) 0),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  sa->proposals[prop][trans].id),
                                  SSH_FORMAT_END);
          if (ret == 0)
            {
              SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
              return 0;
            }
          len += ret;

          if (sa->proposals[prop][trans].transform_attribute)
            {
              ret = ssh_encode_buffer(buffer,
                                      SSH_ENCODE_UINT32(
                                      sa->proposals[prop][trans].
                                      transform_attribute),
                                      SSH_FORMAT_END);

              if (ret == 0)
                {
                  SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
                  return 0;
                }
              len += ret;
            }
        }
    }
  return ikev2_update_len(buffer, len_pos, len);
}

/* Encode KE payload. */
size_t ikev2_encode_ke(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadKE ke,
                       int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_ke_render, ke);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16(
                      (SshUInt16) (4 + 4 + ke->key_exchange_len)),
                      SSH_ENCODE_UINT16((SshUInt16) ke->dh_group),
                      SSH_ENCODE_UINT16((SshUInt16) 0), /* RESERVED */
                      SSH_ENCODE_DATA(
                      ke->key_exchange_data, ke->key_exchange_len),
                      SSH_FORMAT_END);
}

/* Encode ID payload. */
size_t ikev2_encode_id(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadID id,
                       int *next_payload_offset,
                       int id_type)
{
  size_t len;

  SSH_IKEV2_DEBUG_ENCODE(packet, "%.*@",
                         id_type, ssh_ikev2_payload_id_render, id);

  switch (id->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      SSH_ASSERT(id->id_data_size == 4);
      len = 4; break;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      SSH_ASSERT(id->id_data_size == 16);
      len = 16; break;
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      len = id->id_data_size;  break;
    default:
      return 0;
    }
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16((SshUInt16) (4 + 4 + len)),
                      SSH_ENCODE_CHAR((unsigned int) id->id_type),
                      SSH_ENCODE_CHAR((unsigned int) 0), /* RESERVED */
                      SSH_ENCODE_UINT16((SshUInt16) 0), /* RESERVED */
                      SSH_ENCODE_DATA(id->id_data, len),
                      SSH_FORMAT_END);
}

size_t ikev2_encode_idi(SshIkev2Packet packet,
                        SshBuffer buffer,
                        SshIkev2PayloadID id,
                        int *next_payload_offset)
{
  return ikev2_encode_id(packet, buffer, id, next_payload_offset, 1);
}

size_t ikev2_encode_idr(SshIkev2Packet packet,
                        SshBuffer buffer,
                        SshIkev2PayloadID id,
                        int *next_payload_offset)
{
  return ikev2_encode_id(packet, buffer, id, next_payload_offset, 2);
}

#ifdef SSHDIST_IKE_CERT_AUTH
/* Encode Cert payload. */
size_t ikev2_encode_cert(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadCert cert,
                         int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_cert_render, cert);

  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16((SshUInt16) (4 + 1 + cert->cert_size)),
                      SSH_ENCODE_CHAR((unsigned int) cert->cert_encoding),
                      SSH_ENCODE_DATA(cert->cert_data, cert->cert_size),
                      SSH_FORMAT_END);
}

/* Encode certificate request payload. */
size_t ikev2_encode_certreq(SshIkev2Packet packet,
                            SshBuffer buffer,
                            SshIkev2PayloadCertReq cp,
                            int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_certreq_render, cp);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16(
                      (SshUInt16) (4 + 1 + cp->authority_size)),
                      SSH_ENCODE_CHAR((unsigned int) cp->cert_encoding),
                      SSH_ENCODE_DATA(cp->authority_data, cp->authority_size),
                      SSH_FORMAT_END);
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Encode AUTH payload. */
size_t ikev2_encode_auth(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadAuth auth,
                         int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_auth_render, auth);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16(
                      (SshUInt16) (4 + 4 + auth->authentication_size)),
                      SSH_ENCODE_CHAR((unsigned int) auth->auth_method),
                      SSH_ENCODE_CHAR((unsigned int) 0), /* RESERVED */
                      SSH_ENCODE_UINT16((SshUInt16) 0), /* RESERVED */
                      SSH_ENCODE_DATA(
                      auth->authentication_data, auth->authentication_size),
                      SSH_FORMAT_END);
}

/* Encode NONCE payload. */
size_t ikev2_encode_nonce(SshIkev2Packet packet,
                          SshBuffer buffer,
                          SshIkev2PayloadNonce nonce,
                          int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_nonce_render, nonce);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16((SshUInt16) (4 + nonce->nonce_size)),
                      SSH_ENCODE_DATA(nonce->nonce_data, nonce->nonce_size),
                      SSH_FORMAT_END);
}

/* Encode notify payload. */
size_t ikev2_encode_notify(SshIkev2Packet packet,
                           SshBuffer buffer,
                           SshIkev2PayloadNotify notify,
                           int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@",
                         ssh_ikev2_payload_notify_render, notify);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16(
                      (SshUInt16) (4 + 4 + notify->spi_size +
                                   notify->notification_size)),
                      SSH_ENCODE_CHAR((unsigned int) notify->protocol),
                      SSH_ENCODE_CHAR((unsigned int) notify->spi_size),
                      SSH_ENCODE_UINT16(
                      (SshUInt16) notify->notify_message_type),
                      SSH_ENCODE_DATA(notify->spi_data, notify->spi_size),
                      SSH_ENCODE_DATA(
                      notify->notification_data,
                      notify->notification_size),
                      SSH_FORMAT_END);
}

int ikev2_delete_spi_encoder(unsigned char *buf, size_t len, const void *datum)
{
  SshIkev2PayloadDelete d = (SshIkev2PayloadDelete)datum;
  int i;

  if (d->number_of_spis * 4 <= len)
    {
      for(i = 0; i < d->number_of_spis; i++)
        SSH_PUT_32BIT(buf + i * 4, d->spi.spi_array[i]);
    }
  return d->number_of_spis * 4;
}

/* Encode delete payload. */
size_t ikev2_encode_delete(SshIkev2Packet packet,
                           SshBuffer buffer,
                           SshIkev2PayloadDelete d,
                           int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_delete_render, d);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  if (d->spi_size == 4)
    return ssh_encode_buffer(buffer,
                             SSH_ENCODE_CHAR((unsigned int) 0),
                             SSH_ENCODE_CHAR((unsigned int) 0),
                             SSH_ENCODE_UINT16(
                             (SshUInt16) (4 + 4 + d->number_of_spis *
                                          d->spi_size)),
                             SSH_ENCODE_CHAR((unsigned int) d->protocol),
                             SSH_ENCODE_CHAR((unsigned int) d->spi_size),
                             SSH_ENCODE_UINT16((SshUInt16) d->number_of_spis),
                             SSH_ENCODE_SPECIAL(ikev2_delete_spi_encoder, d),
                             SSH_FORMAT_END);
  else
    return
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_CHAR((unsigned int) 0),
                        SSH_ENCODE_CHAR((unsigned int) 0),
                        SSH_ENCODE_UINT16(
                        (SshUInt16) (4 + 4 + d->number_of_spis * d->spi_size)),
                        SSH_ENCODE_CHAR((unsigned int) d->protocol),
                        SSH_ENCODE_CHAR((unsigned int) d->spi_size),
                        SSH_ENCODE_UINT16((SshUInt16) d->number_of_spis),
                        SSH_ENCODE_DATA(
                        d->spi.spi_table,
                        (size_t) (d->number_of_spis * d->spi_size)),
                        SSH_FORMAT_END);
}

/* Encode Vendor ID payload. */
size_t ikev2_encode_vendor_id(SshIkev2Packet packet,
                              SshBuffer buffer,
                              SshIkev2PayloadVendorID vid,
                              int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_vid_render, vid);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16((SshUInt16) (4 + vid->vendorid_size)),
                      SSH_ENCODE_DATA(vid->vendorid_data, vid->vendorid_size),
                      SSH_FORMAT_END);
}

/* Encode TS payload. */
size_t ikev2_encode_ts(SshIkev2Packet packet,
                       SshBuffer buffer,
                       SshIkev2PayloadTS ts,
                       int *next_payload_offset,
                       Boolean tsi)
{
  size_t len, ret, len_pos;
  SshIpAddr addr;
  int i;
#ifdef DEBUG_LIGHT
  SshIkev2PayloadTSItemStruct item[1];

  if (tsi && packet->ed->ipsec_ed->source_ip &&
      SSH_IP_DEFINED(packet->ed->ipsec_ed->source_ip))
    {
      item->start_port = packet->ed->ipsec_ed->source_port;
      item->end_port = packet->ed->ipsec_ed->source_port;
      item->proto = packet->ed->ipsec_ed->protocol;
      *item->start_address = *packet->ed->ipsec_ed->source_ip;
      *item->end_address = *packet->ed->ipsec_ed->source_ip;
      SSH_IKEV2_DEBUG(SSH_D_PCKDMP, ("Trigger packet source %@",
                                     ssh_ikev2_ts_render_item, item));
    }
  else if (!tsi && packet->ed->ipsec_ed->destination_ip &&
           SSH_IP_DEFINED(packet->ed->ipsec_ed->destination_ip))
    {
      item->start_port = packet->ed->ipsec_ed->destination_port;
      item->end_port = packet->ed->ipsec_ed->destination_port;
      item->proto = packet->ed->ipsec_ed->protocol;
      *item->start_address = *packet->ed->ipsec_ed->destination_ip;
      *item->end_address = *packet->ed->ipsec_ed->destination_ip;
      SSH_IKEV2_DEBUG(SSH_D_PCKDMP, ("Triggering packet destination %@",
                                     ssh_ikev2_ts_render_item, item));
    }
#endif /* DEBUG_LIGHT */
  SSH_IKEV2_DEBUG_ENCODE(packet, "%.*@",
                         tsi ? 1 : 2, ssh_ikev2_payload_ts_render, ts);

  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  ret = ssh_encode_buffer(buffer,
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_UINT16((SshUInt16) 0),
                          SSH_FORMAT_END);
  if (ret == 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
      return 0;
    }
  len_pos = ssh_buffer_len(buffer) - 2;

  if (tsi)
    addr = packet->ed->ipsec_ed->source_ip;
  else
    addr = packet->ed->ipsec_ed->destination_ip;

  if (addr && SSH_IP_DEFINED(addr))
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_CHAR(
                              (unsigned int) ts->number_of_items_used + 1),
                              SSH_ENCODE_CHAR((unsigned int) 0),
                              SSH_ENCODE_UINT16((SshUInt16) 0),
                              SSH_FORMAT_END);
      if (len == 0)
        return 0;

      if (SSH_IP_IS4(addr))
        {
          ret = ssh_encode_buffer(buffer,
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) SSH_IKEV2_TS_IPV4_ADDR_RANGE),
                                  SSH_ENCODE_CHAR(
                                  (unsigned int)
                                  packet->ed->ipsec_ed->protocol),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) 16), /* Length */
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  (tsi ?
                                   packet->ed->ipsec_ed->source_port :
                                   packet->ed->ipsec_ed->destination_port)),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  (tsi ?
                                   packet->ed->ipsec_ed->source_port :
                                   packet->ed->ipsec_ed->destination_port)),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(addr), (size_t) 4),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(addr), (size_t) 4),
                                  SSH_FORMAT_END);
        }
      else
        {
          ret = ssh_encode_buffer(buffer,
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) SSH_IKEV2_TS_IPV6_ADDR_RANGE),
                                  SSH_ENCODE_CHAR(
                                  (unsigned int)
                                  packet->ed->ipsec_ed->protocol),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) 40), /* Length */
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  (tsi ?
                                   packet->ed->ipsec_ed->source_port :
                                   packet->ed->ipsec_ed->destination_port)),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16)
                                  (tsi ?
                                   packet->ed->ipsec_ed->source_port :
                                   packet->ed->ipsec_ed->destination_port)),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(addr), (size_t) 16),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(addr), (size_t) 16),
                                  SSH_FORMAT_END);

        }
      if (ret == 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
          return 0;
        }
      len += ret;
    }
  else
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_CHAR(
                              (unsigned int) ts->number_of_items_used),
                              SSH_ENCODE_CHAR((unsigned int) 0),
                              SSH_ENCODE_UINT16((SshUInt16) 0),
                              SSH_FORMAT_END);
      if (len == 0)
        return 0;
    }

  for(i = 0; i < ts->number_of_items_used; i++)
    {
      switch (ts->items[i].ts_type)
        {
        case SSH_IKEV2_TS_IPV4_ADDR_RANGE:
          SSH_ASSERT(SSH_IP_IS4(ts->items[i].start_address));
          SSH_ASSERT(SSH_IP_IS4(ts->items[i].end_address));
          ret = ssh_encode_buffer(buffer,
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) ts->items[i].ts_type),
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) ts->items[i].proto),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) 16), /* Length */
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) ts->items[i].start_port),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) ts->items[i].end_port),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(ts->items[i].start_address),
                                  (size_t) 4),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(ts->items[i].end_address),
                                  (size_t) 4),
                                  SSH_FORMAT_END);
          break;
        case SSH_IKEV2_TS_IPV6_ADDR_RANGE:
          SSH_ASSERT(SSH_IP_IS6(ts->items[i].start_address));
          SSH_ASSERT(SSH_IP_IS6(ts->items[i].end_address));
          ret = ssh_encode_buffer(buffer,
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) ts->items[i].ts_type),
                                  SSH_ENCODE_CHAR(
                                  (unsigned int) ts->items[i].proto),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) 40), /* Length */
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) ts->items[i].start_port),
                                  SSH_ENCODE_UINT16(
                                  (SshUInt16) ts->items[i].end_port),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(ts->items[i].start_address),
                                  (size_t) 16),
                                  SSH_ENCODE_DATA(
                                  SSH_IP_ADDR_DATA(ts->items[i].end_address),
                                  (size_t) 16),
                                  SSH_FORMAT_END);
          break;
        }
      if (ret == 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
          return 0;
        }
      len += ret;
    }
  return ikev2_update_len(buffer, len_pos, len);
}

/* Encode Conf payload. */
size_t ikev2_encode_conf(SshIkev2Packet packet,
                         SshBuffer buffer,
                         SshIkev2PayloadConf conf,
                         int *next_payload_offset)
{
  size_t len, ret;
  int i, len_pos;

  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_conf_render, conf);

  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  ret = ssh_encode_buffer(buffer,
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_UINT16((SshUInt16) 0),
                          SSH_FORMAT_END);
  if (ret == 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
      return 0;
    }
  len_pos = ssh_buffer_len(buffer) - 2;

  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_CHAR((unsigned int) conf->conf_type),
                          SSH_ENCODE_CHAR((unsigned int) 0),
                          SSH_ENCODE_UINT16((SshUInt16) 0),
                          SSH_FORMAT_END);
  if (len == 0)
    return 0;

  for(i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      ret = ssh_encode_buffer(buffer,
                              SSH_ENCODE_UINT16(
                              (SshUInt16)
                              conf->conf_attributes[i].attribute_type),
                              SSH_ENCODE_UINT16(
                              (SshUInt16)
                              conf->conf_attributes[i].length),
                              SSH_ENCODE_DATA(
                              conf->conf_attributes[i].value,
                              conf->conf_attributes[i].length),
                              SSH_FORMAT_END);
      if (ret == 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Encode buffer error"));
          return 0;
        }
      len += ret;
    }
  return ikev2_update_len(buffer, len_pos, len);
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* Encode EAP payload. */
size_t ikev2_encode_eap(SshIkev2Packet packet,
                        SshBuffer buffer,
                        SshIkev2PayloadEap eap,
                        int *next_payload_offset)
{
  SSH_IKEV2_DEBUG_ENCODE(packet, "%@", ssh_ikev2_payload_eap_render, eap);
  if (next_payload_offset != NULL)
    *next_payload_offset = ssh_buffer_len(buffer);
  return
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_CHAR((unsigned int) 0),
                      SSH_ENCODE_UINT16((SshUInt16) (4 + eap->eap_size)),
                      SSH_ENCODE_DATA(eap->eap_data, eap->eap_size),
                      SSH_FORMAT_END);
}
#endif /* SSHDIST_IKE_EAP_AUTH */


/* Helper function to update len at `len_pos' of the buffer.
   Return the length of 0 in case of error. */
size_t ikev2_update_len(SshBuffer buffer, size_t len_pos, size_t len)
{
  unsigned char *p;

  len += 4;
  if (len > SSH_IKEV2_MAX_PAYLOAD_SIZE)
    return 0;
  p = ssh_buffer_ptr(buffer);
  SSH_PUT_16BIT(p + len_pos, len);
  return len;
}

/* Update the next payload. */
void ikev2_update_next_payload(SshIkev2Packet packet,
                               SshIkev2PayloadType next_payload)
{
  unsigned char *p;

  if (packet->ed->next_payload_offset == -1)
    {
      packet->first_payload = next_payload;
    }
  else
    {
      p = ssh_buffer_ptr(packet->ed->buffer);
      p[packet->ed->next_payload_offset] = next_payload;
    }
}
