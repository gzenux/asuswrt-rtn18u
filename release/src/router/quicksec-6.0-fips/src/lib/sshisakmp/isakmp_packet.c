/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp packet functions module.
*/

#include "sshincludes.h"
#include "sshbufaux.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkePacketEncode"

/* Append one string pointer and length to the packet buffer. Update total
   length of the packet in the (l). */
#define APPEND_PTR(b,p,s,l) do {                         \
    if (ssh_buffer_append((b),(p),(s)) != SSH_BUFFER_OK) \
      goto error;                                        \
    (l)+=(s);                                            \
  } while (0)

/* Append one character to the packet buffer. Update total length of the packet
   in the (l). */
#define APPEND_CHAR(b,p,l) do {                 \
    unsigned char *ptr;                         \
    if (((p) & 0xff) != (p))                    \
      {                                         \
        SSH_IKE_DEBUG(3, negotiation,                                 \
                      ("Value %d exceeds field width (8 bit)", (p))); \
        goto error_payload_malformed;                                 \
      }                                                               \
    if (ssh_buffer_append_space((b), &ptr, 1) != SSH_BUFFER_OK)       \
      goto error;                                                     \
    *ptr = p;                                                         \
    (l)+=1;                                                           \
  } while (0)

/* Append one 32 bit integer to the packet buffer. Update total length of the
   packet in the (l). */
#define APPEND_INT32(b,d,l) do {                \
        unsigned char buf[4];                   \
        if (((d) & 0xffffffff) != (d))          \
          {                                     \
            SSH_IKE_DEBUG(3, negotiation,                               \
                          ("Value %ld exceeds field width (32 bit)",    \
                           (unsigned long) (d)));                       \
            goto error_payload_malformed;                               \
          }                                                             \
        SSH_IKE_PUT32(buf, (d));                                        \
        if (ssh_buffer_append((b), buf, 4) != SSH_BUFFER_OK)            \
          goto error;                                                   \
        (l) += 4;                                                       \
      } while (0)

/* Append one 16 bit integer to the packet buffer. Update total length of the
   packet in the (l). */
#define APPEND_INT16(b,d,l) do {                \
    unsigned char buf[2];                       \
    if (((d) & 0xffff) != (d))                  \
      {                                                                 \
        SSH_IKE_DEBUG(3, negotiation,                                   \
                      ("Value %d exceeds field width (16 bit)", (d)));  \
        goto error_payload_malformed;                                   \
      }                                                                 \
    SSH_IKE_PUT16(buf, (d));                                            \
    if (ssh_buffer_append((b), buf, 2) != SSH_BUFFER_OK)                \
      goto error;                                                       \
    (l) += 2;                                                           \
  } while (0)

/* Append one data attribute to the packet buffer. Update total length of the
   packet in the (l). */
#define APPEND_DA(n,b,d,l) do { \
     size_t ret; \
     ret = ssh_ike_encode_data_attribute((b), (d), (0)); \
     if (ret == -1) \
       goto error; \
     (l) += ret; \
  } while (0)

/*                                                              shade{0.9}
 * Encode isakmp packet from SshIkePacket structure and
 * append it to buffer. SshBuffer is cleared before appending
 * packet.                                                      shade{1.0}
 */
SshIkeNotifyMessageType ike_encode_packet(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshBuffer buffer)
{
  SshIkeNotifyMessageType ret;
  size_t len, tmp_len;
  size_t isakmp_packet_len_offset, isakmp_encrypt_start_offset;
  SshIkePayload payload;
  unsigned char *p;
  int i, j, k, l, m;

  ike_debug_encode_start(negotiation);

  SSH_DEBUG(5, ("Start, SA = { 0x%08lx %08lx - %08lx %08lx } / %08lx, "
                "nego = %d",
                (unsigned long)
                SSH_IKE_GET32(isakmp_packet->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(isakmp_packet->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(isakmp_packet->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(isakmp_packet->cookies.responder_cookie + 4),
                (unsigned long)
                isakmp_packet->message_id,
                negotiation->negotiation_index));

  ssh_buffer_clear(buffer);
  len = 0;
  if (isakmp_packet->number_of_payload_packets == 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No payloads to encode"));
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  APPEND_PTR(buffer, isakmp_packet->cookies.initiator_cookie,
             SSH_IKE_COOKIE_LENGTH, len);
  APPEND_PTR(buffer, isakmp_packet->cookies.responder_cookie,
             SSH_IKE_COOKIE_LENGTH, len);
  SSH_IKE_DEBUG(8, negotiation,
                ("Encode packet, version = %d.%d, flags = 0x%08x",
                 isakmp_packet->major_version, isakmp_packet->minor_version,
                 isakmp_packet->flags));
  if (isakmp_packet->payloads[0]->type == SSH_IKE_PAYLOAD_TYPE_PRV)
    APPEND_CHAR(buffer,
                isakmp_packet->payloads[0]->pl.prv.prv_payload_id,
                len);
  else
    APPEND_CHAR(buffer, isakmp_packet->payloads[0]->type, len);
  APPEND_CHAR(buffer, isakmp_packet->major_version << 4 |
              isakmp_packet->minor_version, len);
  APPEND_CHAR(buffer, isakmp_packet->exchange_type, len);
  APPEND_CHAR(buffer, isakmp_packet->flags, len);
  APPEND_INT32(buffer, isakmp_packet->message_id, len);
  isakmp_packet_len_offset = len;
  APPEND_INT32(buffer, 0, len);
  isakmp_encrypt_start_offset = len;
  for (i = 0; i < isakmp_packet->number_of_payload_packets; i++)
    {
      size_t payload_len_offset;

      payload = isakmp_packet->payloads[i];
      payload->payload_offset = len - SSH_IKE_PACKET_GENERIC_HEADER_LEN;
      if (i == isakmp_packet->number_of_payload_packets - 1)
        APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_NONE, len);
      else
        {
          if (isakmp_packet->payloads[i + 1]->type == SSH_IKE_PAYLOAD_TYPE_PRV)
            APPEND_CHAR(buffer,
                        isakmp_packet->payloads[i + 1]->pl.
                        prv.prv_payload_id,
                        len);
          else
            APPEND_CHAR(buffer, isakmp_packet->payloads[i + 1]->type, len);
        }
      APPEND_CHAR(buffer, 0, len);
      payload_len_offset = len;
      APPEND_INT16(buffer, 0, len);
      switch (payload->type)
        {
        case SSH_IKE_PAYLOAD_TYPE_SA:
          SSH_IKE_DEBUG_ENCODE(9, negotiation,
                        "Encode SA: doi = %d, sit = 0x%x",
                        payload->pl.sa.doi,
                        (int) payload->pl.sa.situation.situation_flags);
          /* Doi specific */
          APPEND_INT32(buffer, payload->pl.sa.doi, len);
          APPEND_INT32(buffer,
                       payload->pl.sa.situation.situation_flags,
                       len);
          if ((payload->pl.sa.situation.situation_flags &
               SSH_IKE_SIT_SECRECY) ||
              (payload->pl.sa.situation.situation_flags &
               SSH_IKE_SIT_INTEGRITY))
            {
              SSH_IKE_DEBUG_ENCODE(9, negotiation, "labeled_domain_identifier "
                                             "= %d (0x%x)",
                                             (int) payload->pl.sa.situation.
                                             labeled_domain_identifier,
                                             (int) payload->pl.sa.situation.
                                             labeled_domain_identifier);
              APPEND_INT32(buffer,
                           payload->pl.sa.situation.labeled_domain_identifier,
                           len);
              if (payload->pl.sa.situation.situation_flags &
                  SSH_IKE_SIT_SECRECY)
                {
                  SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Secrecy level",
                                       payload->pl.sa.situation.
                                       secrecy_level_length,
                                       payload->pl.sa.situation.
                                       secrecy_level_data);
                  SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Secrecy bitmap",
                                       payload->pl.sa.situation.
                                       secrecy_category_bitmap_length,
                                       payload->pl.sa.situation.
                                       secrecy_category_bitmap_data);
                  APPEND_INT16(buffer,
                               payload->pl.sa.situation.secrecy_level_length,
                               len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_PTR(buffer,
                             payload->pl.sa.situation.secrecy_level_data,
                             payload->pl.sa.situation.secrecy_level_length,
                             len);
                  while (len % 4 != 0)
                    APPEND_CHAR(buffer, 0, len);
                  APPEND_INT16(buffer,
                               payload->pl.sa.situation
                               .secrecy_category_bitmap_length,
                               len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_CHAR(buffer, 0, len);
                  tmp_len =
                    (payload->pl.sa.situation.secrecy_category_bitmap_length +
                     7) / 8;
                  APPEND_PTR(buffer,
                             payload->pl.sa.situation
                             .secrecy_category_bitmap_data,
                             tmp_len,
                             len);
                  while (len % 4 != 0)
                    APPEND_CHAR(buffer, 0, len);
                }
              if (payload->pl.sa.situation.situation_flags &
                  SSH_IKE_SIT_INTEGRITY)
                {
                  SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation,"Integrity level",
                                       payload->pl.sa.situation.
                                       integrity_level_length,
                                       payload->pl.sa.situation.
                                       integrity_level_data);
                  SSH_IKE_DEBUG_BUFFER_ENCODE(9,negotiation,"Integrity bitmap",
                                       payload->pl.sa.situation.
                                       integrity_category_bitmap_length,
                                       payload->pl.sa.situation.
                                       integrity_category_bitmap_data);
                  APPEND_INT16(buffer,
                               payload->pl.sa.situation.integrity_level_length,
                               len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_PTR(buffer,
                             payload->pl.sa.situation.integrity_level_data,
                             payload->pl.sa.situation.integrity_level_length,
                             len);
                  while (len % 4 != 0)
                    APPEND_CHAR(buffer, 0, len);
                  APPEND_INT16(buffer,
                               payload->pl.sa.situation
                               .integrity_category_bitmap_length,
                               len);
                  APPEND_CHAR(buffer, 0, len);
                  APPEND_CHAR(buffer, 0, len);
                  tmp_len =
                    (payload->pl.sa.situation.integrity_category_bitmap_length
                     + 7) / 8;
                  APPEND_PTR(buffer,
                             payload->pl.sa.situation
                             .integrity_category_bitmap_data,
                             tmp_len,
                             len);
                  while (len % 4 != 0)
                    APPEND_CHAR(buffer, 0, len);
                }
            }
          if (payload->pl.sa.number_of_proposals == 0)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Number of proposals is 0"));
              return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
            }
          for (j = 0; j < payload->pl.sa.number_of_proposals; j++)
            {
              if (payload->pl.sa.proposals[j].number_of_protocols == 0)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Number of protocols[%d] is 0", j));
                  return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
                }

              for (k = 0;
                  k < payload->pl.sa.proposals[j].number_of_protocols;
                  k++)
                {
                  size_t p_payload_len_offset, p_payload_start_offset;
                  size_t t_payload_len_offset, t_payload_start_offset;
                  SshIkePayloadPProtocol prot;

                  p_payload_start_offset = len;
                  prot = &payload->pl.sa.proposals[j].protocols[k];
                  SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                              prot->spi_size, prot->spi,
                                              "Encode SA: Proposal[%d] = %d "
                                              ".protocol[%d] = %d, "
                                              "# transforms = %d, spi",
                                              j, payload->pl.sa.
                                              proposals[j].proposal_number,
                                              k, prot->protocol_id,
                                              prot->number_of_transforms);

                  if (k + 1 <
                      payload->pl.sa.proposals[j].number_of_protocols
                      || j + 1 < payload->pl.sa.number_of_proposals)
                    APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_P, len);
                  else
                    APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_NONE, len);
                  APPEND_CHAR(buffer, 0, len);
                  p_payload_len_offset = len;
                  APPEND_INT16(buffer, 0, len);
                  APPEND_CHAR(buffer,
                              payload->pl.sa.proposals[j].proposal_number,
                              len);
                  APPEND_CHAR(buffer, prot->protocol_id, len);
                  APPEND_CHAR(buffer, prot->spi_size, len);
                  APPEND_CHAR(buffer, prot->number_of_transforms, len);
                  APPEND_PTR(buffer, prot->spi, prot->spi_size, len);

                  if (prot->number_of_transforms == 0)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Number of transforms[%d][%d] is 0",
                                     j, k));
                      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
                    }

                  for (l = 0; l < prot->number_of_transforms; l++)
                    {
                      SSH_IKE_DEBUG_ENCODE(9, negotiation,
                                    "Encode SA: trans[%d] = %d, id = %d, "
                                    "# sa = %d",
                                    l, prot->transforms[l].transform_number,
                                    prot->transforms[l].transform_id.generic,
                                    prot->transforms[l].
                                    number_of_sa_attributes);
                      t_payload_start_offset = len;
                      if (l + 1 < prot->number_of_transforms)
                        APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_T, len);
                      else
                        APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_NONE, len);
                      APPEND_CHAR(buffer, 0, len);
                      t_payload_len_offset = len;
                      APPEND_INT16(buffer, 0, len);
                      APPEND_CHAR(buffer, prot->transforms[l].transform_number,
                                  len);
                      APPEND_CHAR(buffer,
                                  prot->transforms[l].transform_id.generic,
                                  len);
                      APPEND_INT16(buffer, 0, len);

                      for (m = 0;
                          m < prot->transforms[l].number_of_sa_attributes;
                          m++)
                        {
                          APPEND_DA(negotiation, buffer,
                                    &(prot->transforms[l].sa_attributes[m]),
                                    len);
                          SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(11, negotiation,
                                                      prot->transforms[l].
                                                      sa_attributes[m].
                                                      attribute_length,
                                                      prot->transforms[l].
                                                      sa_attributes[m].
                                                      attribute,
                                                      "Encode SA: da[%d], "
                                                      "type = %d, value",
                                                      m,
                                                      prot->transforms[l].
                                                      sa_attributes[m].
                                                      attribute_type);
                        }
                      /* Update length */
                      p = ssh_buffer_ptr(buffer) + t_payload_len_offset;
                      SSH_IKE_PUT16(p, len - t_payload_start_offset);
                    }
                  /* Update length */
                  p = ssh_buffer_ptr(buffer) + p_payload_len_offset;
                  SSH_IKE_PUT16(p, len - p_payload_start_offset);
                }
            }
          break;
        case SSH_IKE_PAYLOAD_TYPE_KE:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode KE: ke",
                               payload->pl.ke.key_exchange_data_len,
                               payload->pl.ke.key_exchange_data);
          APPEND_PTR(buffer, payload->pl.ke.key_exchange_data,
                     payload->pl.ke.key_exchange_data_len, len);
          break;
        case SSH_IKE_PAYLOAD_TYPE_ID:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode ID: packet",
                               payload->payload_length,
                               payload->pl.id.raw_id_packet);
          /* Doi specific */
          APPEND_PTR(buffer, payload->pl.id.raw_id_packet,
                     payload->payload_length, len);
          break;
#ifdef SSHDIST_IKE_CERT_AUTH
        case SSH_IKE_PAYLOAD_TYPE_CERT:
          SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                      payload->pl.cert.certificate_data_len,
                                      payload->pl.cert.certificate_data,
                                      "Encode CERT: encoding = %d, data",
                                      payload->pl.cert.cert_encoding);
          APPEND_CHAR(buffer, payload->pl.cert.cert_encoding, len);
          APPEND_PTR(buffer, payload->pl.cert.certificate_data,
                     payload->pl.cert.certificate_data_len, len);
          break;
        case SSH_IKE_PAYLOAD_TYPE_CR:
          SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                      payload->pl.cr.
                                      certificate_authority_len,
                                      payload->pl.cr.
                                      certificate_authority,
                                      "Encode CR: new, type = %d, value",
                                      payload->pl.cr.certificate_type);
          APPEND_CHAR(buffer, payload->pl.cr.certificate_type, len);
          APPEND_PTR(buffer, payload->pl.cr.certificate_authority,
                     payload->pl.cr.certificate_authority_len, len);
          break;
#endif /* SSHDIST_IKE_CERT_AUTH */
        case SSH_IKE_PAYLOAD_TYPE_HASH:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode HASH: hash",
                               payload->payload_length,
                               payload->pl.hash.hash_data);
          APPEND_PTR(buffer, payload->pl.hash.hash_data,
                     payload->payload_length, len);
          break;
#ifdef SSHDIST_IKE_CERT_AUTH
        case SSH_IKE_PAYLOAD_TYPE_SIG:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode SIG: sig",
                               payload->payload_length,
                               payload->pl.sig.signature_data);
          APPEND_PTR(buffer, payload->pl.sig.signature_data,
                     payload->payload_length, len);
          break;
#endif /* SSHDIST_IKE_CERT_AUTH */
        case SSH_IKE_PAYLOAD_TYPE_NONCE:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode NONCE: nonce",
                               payload->payload_length,
                               payload->pl.nonce.raw_nonce_packet);
          APPEND_PTR(buffer, payload->pl.nonce.raw_nonce_packet,
                     payload->payload_length, len);
          break;
        case SSH_IKE_PAYLOAD_TYPE_N:
          SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                      payload->pl.n.spi_size,
                                      payload->pl.n.spi,
                                      "Encode N: doi = %d, "
                                      "proto = %d, type = %d, spi",
                                      payload->pl.n.doi,
                                      payload->pl.n.protocol_id,
                                      payload->pl.n.notify_message_type);
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode N: data",
                               payload->pl.n.notification_data_size,
                               payload->pl.n.notification_data);
          /* Doi specific */
          APPEND_INT32(buffer, payload->pl.n.doi, len);
          APPEND_CHAR(buffer, payload->pl.n.protocol_id, len);
          APPEND_CHAR(buffer, payload->pl.n.spi_size, len);
          APPEND_INT16(buffer, payload->pl.n.notify_message_type, len);
          APPEND_PTR(buffer, payload->pl.n.spi,
                     payload->pl.n.spi_size, len);
          APPEND_PTR(buffer, payload->pl.n.notification_data,
                     payload->pl.n.notification_data_size, len);
          break;
        case SSH_IKE_PAYLOAD_TYPE_D:
          SSH_IKE_DEBUG_ENCODE(9, negotiation,
                        "Encode D: doi = %d, proto = %d, # spis = %d",
                        payload->pl.d.doi, payload->pl.d.protocol_id,
                        payload->pl.d.number_of_spis);
          /* Doi specific */
          APPEND_INT32(buffer, payload->pl.d.doi, len);
          APPEND_CHAR(buffer, payload->pl.d.protocol_id, len);
          APPEND_CHAR(buffer, payload->pl.d.spi_size, len);
          APPEND_INT16(buffer, payload->pl.d.number_of_spis, len);
          for (j = 0; j < payload->pl.d.number_of_spis; j++)
            {
              /* Should each spi size be padded to 32 bit? */
              APPEND_PTR(buffer, payload->pl.d.spis[j],
                         payload->pl.d.spi_size, len);
              SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(11, negotiation,
                                          payload->pl.d.spi_size,
                                          payload->pl.d.spis[j],
                                          "Encode D: spi[%d]", j);
            }
          break;
        case SSH_IKE_PAYLOAD_TYPE_VID:
          SSH_IKE_DEBUG_BUFFER_ENCODE(9, negotiation, "Encode VID: vendor id",
                               payload->payload_length,
                               payload->pl.vid.vid_data);
          APPEND_PTR(buffer, payload->pl.vid.vid_data,
                     payload->payload_length, len);
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_PAYLOAD_TYPE_ATTR:
          SSH_IKE_DEBUG_ENCODE(9, negotiation,
                        "Encode ATTR: attributes, type = %d, "
                        "id = %d, # attrs = %d",
                        payload->pl.attr.type,
                        payload->pl.attr.identifier,
                        payload->pl.attr.number_of_attributes);
          APPEND_CHAR(buffer, payload->pl.attr.type, len);
          APPEND_CHAR(buffer, 0, len);
          APPEND_INT16(buffer, payload->pl.attr.identifier, len);
          for (j = 0; j < payload->pl.attr.number_of_attributes; j++)
            {
              APPEND_DA(negotiation, buffer,
                        &(payload->pl.attr.attributes[j]),
                        len);
              SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                          payload->pl.attr.attributes[j].
                                          attribute_length,
                                          payload->pl.attr.attributes[j].
                                          attribute,
                                          "Encode ATTR: da[%d], type = %d, "
                                          "value",
                                          j,
                                          payload->pl.attr.attributes[j].
                                          attribute_type);
            }
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        case SSH_IKE_PAYLOAD_TYPE_PRV:
          SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE(9, negotiation,
                                      payload->payload_length,
                                      payload->pl.prv.data,
                                      "Encode PRV[%d]: data",
                                      payload->pl.prv.prv_payload_id);
          APPEND_PTR(buffer, payload->pl.prv.data, payload->payload_length,
                     len);
          break;
        default:
          ssh_fatal("Internal error in ike_encode_packet, got "
                    "invalid packet type: %d", payload->type);
          break;
        }
      /* Update payload length */
      p = ssh_buffer_ptr(buffer) + payload_len_offset;
      SSH_IKE_PUT16(p, len - (payload->payload_offset +
                              SSH_IKE_PACKET_GENERIC_HEADER_LEN));
      SSH_DEBUG(9, ("Payload length = %d",
                    len - (payload->payload_offset +
                           SSH_IKE_PACKET_GENERIC_HEADER_LEN)));
      payload->payload_length = len - SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN -
        (payload->payload_offset + SSH_IKE_PACKET_GENERIC_HEADER_LEN);
      if (payload->payload_length >= 65536)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Payload length exceeds 64k: %d",
                                         payload->payload_length));
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }
    }

  if (len >= SSH_IKE_MAX_PACKET_LEN)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Packet length exceeds 64k: %d", len));
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  isakmp_packet->length = len;

  /* Add padding */
  if (isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION)
    {
      if (negotiation->ed->encryption_cipher == NULL)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Trying to encrypt, but no encryption "
                         "context initialized"));
          return SSH_IKE_NOTIFY_MESSAGE_NO_SA_ESTABLISHED;
        }

      /* Pad to block length */
      while ((len - SSH_IKE_PACKET_GENERIC_HEADER_LEN) %
             negotiation->ed->cipher_block_length != 0)
        APPEND_CHAR(buffer, 0, len);
    }

  /* Temporarely set payload_starts to point in buffer, so finalize
     functions can modify packet, before encrypting it.
     Also set the encoded_packet to point to packet, so we can use the full
     packet to calculate HASH. */
  p = ssh_buffer_ptr(buffer);

  /* Update length to reflect padded length */
  SSH_IKE_PUT32(p + isakmp_packet_len_offset, len);
  /* Take a copy before running finalizers. Finalizers only change the packet
     going out, the packet in memory stays unmodified. */
  isakmp_packet->encoded_packet = ssh_memdup(ssh_buffer_ptr(buffer), len);
  if (isakmp_packet->encoded_packet == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  isakmp_packet->encoded_packet_len = len;
  for (i = 0; i < isakmp_packet->number_of_payload_packets; i++)
    {
      isakmp_packet->payloads[i]->payload_start =
        p + isakmp_packet->payloads[i]->payload_offset +
        SSH_IKE_PACKET_GENERIC_HEADER_LEN;
    }

  SSH_DEBUG(9, ("Packet length = %d", len));
  for (i = 0; i < isakmp_packet->number_of_payload_packets; i++)
    {
      payload = isakmp_packet->payloads[i];
      if (payload->func != NULL_FNPTR)
        {
          SSH_DEBUG(8, ("Calling finalizing function for "
                        "payload[%d].type = %d",
                        i, payload->type));
          ret = (*payload->func)(isakmp_context, isakmp_sa, negotiation,
                                 isakmp_packet, i, payload);
          if (ret != 0)
            return ret;
        }
    }

  /* Change payload_start pointers to point back to unmodified packet. */
  for (i = 0; i < isakmp_packet->number_of_payload_packets; i++)
    {
      isakmp_packet->payloads[i]->payload_start =
        isakmp_packet->encoded_packet +
        isakmp_packet->payloads[i]->payload_offset +
        SSH_IKE_PACKET_GENERIC_HEADER_LEN;
    }

  SSH_IKE_DEBUG_BUFFER(11, negotiation, "Encoded packet",
                       len, ssh_buffer_ptr(buffer));

  {
    unsigned char ipaddr[64];
    ikev1_list_packet_payloads(isakmp_packet,
        isakmp_packet->payloads,
        ike_ip_string(negotiation->sa->server_context->ip_address,
                  ipaddr, sizeof(ipaddr)),
        negotiation->sa->use_natt ?
          negotiation->sa->server_context->nat_t_local_port :
          negotiation->sa->server_context->normal_local_port,
        negotiation->sa->isakmp_negotiation->ike_pm_info->remote_ip,
        negotiation->sa->server_context->normal_remote_port,
        TRUE);
  }

  /* Encrypt if needed */
  if (isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION)
    {
      SshCryptoStatus cret;

      SSH_DEBUG(7, ("Encrypting packet"));
      p = ssh_buffer_ptr(buffer) + isakmp_encrypt_start_offset;

      SSH_IKE_DEBUG_BUFFER(9, negotiation,
                          "dec->enc IV",
                          negotiation->sa->cipher_iv_len,
                          negotiation->ed->cipher_iv);

      cret = ssh_cipher_set_iv(negotiation->ed->encryption_cipher,
                               negotiation->ed->cipher_iv);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation, ("ssh_cipher_set_iv failed: %.200s",
                                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      cret = ssh_cipher_start(negotiation->ed->encryption_cipher);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_start encrypt failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      cret = ssh_cipher_transform(negotiation->ed->encryption_cipher,
                                  p, p, len -
                                  SSH_IKE_PACKET_GENERIC_HEADER_LEN);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_transform encrypt failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      /* Copy the last bytes of the encrypted packet to cipher_iv */
      memcpy(negotiation->ed->cipher_iv,
             p + len - SSH_IKE_PACKET_GENERIC_HEADER_LEN -
             negotiation->sa->cipher_iv_len,
             negotiation->sa->cipher_iv_len);

      SSH_IKE_DEBUG_BUFFER(9, negotiation,
                           "enc->dec IV",
                           negotiation->sa->cipher_iv_len,
                           negotiation->ed->cipher_iv);

      cret = ssh_cipher_set_iv(negotiation->ed->decryption_cipher,
                               negotiation->ed->cipher_iv);

      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation, ("ssh_cipher_set_iv failed: %.200s",
                                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }
      SSH_IKE_DEBUG_BUFFER(11, negotiation, "Encrypted packet",
                           len, ssh_buffer_ptr(buffer));

    }
  /* Update length */
  p = ssh_buffer_ptr(buffer) + isakmp_packet_len_offset;
  SSH_IKE_PUT32(p, len);
  SSH_DEBUG(7, ("Final length = %d", len));

  ike_debug_packet_out(negotiation, isakmp_packet);

  return 0;
 error:
  return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
 error_payload_malformed:
  return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
}

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshIkePacketDecode"

/*                                                              shade{0.9}
 * Decode transform-packet from SA-payload                      shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_t(SshIkeContext isakmp_context,
                                             SshIkeNegotiation negotiation,
                                             SshIkePayloadT t_payload,
                                             unsigned char *p,
                                             size_t packet_len,
                                             int number_of_transforms)
{
  size_t ind, ind2, payload_len, attr_len;
  int trans_ind, sa_attrib_cnt;
  SshIkePayloadType next_payload_type;

  SSH_DEBUG(5, ("Start, # trans = %d", number_of_transforms));
  ind = 0;
  if (number_of_transforms == 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Number of transforms is 0"));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX,
                    "Transform payload did not contain any transforms");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                          NULL, 0, -1,
                          "Number of transforms is zero");
      return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
    }
  for (trans_ind = 0; trans_ind < number_of_transforms; trans_ind++)
    {
      if (packet_len < ind + 8)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Short packet : %d < %d", packet_len, ind + 8));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Packet does not contain enough data for all "
                        "transforms");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                              p, packet_len, ind + 8,
                              "Packet does not contain enough data "
                              "for all transforms");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }

      next_payload_type = SSH_IKE_GET8(p + ind);
      if (next_payload_type != SSH_IKE_PAYLOAD_TYPE_T)
        {
          if (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE ||
              trans_ind != number_of_transforms - 1)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Invalid payload type = %d", next_payload_type));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                            "Invalid payload type in proposal payload");
              SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                                  p, packet_len, ind,
                  "Next payload inside P payload must be T or NONE");
              return SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE;
            }
        }

      if (SSH_IKE_GET8(p + ind + 1) != 0)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Reserved 1 not 0"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                        "Generic payload header reserved not zero in "
                        "transform payload");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                          p, packet_len, ind + 1,
                          "Reserved not 0");
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      payload_len = SSH_IKE_GET16(p + ind + 2);

      if (payload_len > packet_len)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet: %d < %d",
                                         packet_len, payload_len));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Packet does not contain enough data for transform "
                        "payload");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                              p, packet_len, ind + 2,
                              "Packet does not contain enough data "
                              "for all transforms");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }

      t_payload[trans_ind].transform_number = SSH_IKE_GET8(p + ind + 4);
#if 0
      if (t_payload[trans_ind].transform_number != trans_ind + 1)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid tranform number = %d, "
                                         "should be %d",
                                         t_payload[trans_ind].transform_number,
                                         trans_ind + 1));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX,
                        "Transform numbers does not increment by 1");
          return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
        }
#endif
      t_payload[trans_ind].transform_id.generic = SSH_IKE_GET8(p + ind + 5);
      if (SSH_IKE_GET16(p + ind + 6) != 0)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Reserved 2 not 0"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                        "Transform payload reserved 2 not zero");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                          p, packet_len, ind + 6,
                          "Reserved not 0");
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      sa_attrib_cnt = 0;
      ind2 = 8;
      while (ind2 + 4 <= payload_len)
        {
          attr_len =
            ssh_ike_decode_data_attribute_size(p + ind + ind2, 0);
          ind2 += attr_len;
          sa_attrib_cnt++;
        }
      if (ind2 > payload_len)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Data attribute too long len = %d, payload_len = %d",
                         ind2, payload_len));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Packet does not contain enough data for data "
                        "attribute inside transform payload");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                              p, packet_len, ind2,
                              "Packet does not contain enough data "
                              "for attribute inside tranform payload");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }
      if (ind2 < payload_len)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Warning Junk after last da"));
        }
      t_payload[trans_ind].sa_attributes =
        ssh_calloc(sa_attrib_cnt, sizeof(struct SshIkeDataAttributeRec));
      if (t_payload[trans_ind].sa_attributes == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      t_payload[trans_ind].number_of_sa_attributes = sa_attrib_cnt;


      SSH_IKE_DEBUG_DECODE(9, negotiation,
                    "Decode SA: trans[%d] = %d, id = %d, # sa = #%d",
                    trans_ind, t_payload[trans_ind].transform_number,
                    t_payload[trans_ind].transform_id.generic,
                    t_payload[trans_ind].number_of_sa_attributes);

      sa_attrib_cnt = 0;
      ind2 = 8;
      while (ind2 + 4 <= payload_len)
        {
          if (!ssh_ike_decode_data_attribute(p + ind + ind2,
                                             payload_len - ind2,
                                             &attr_len,
                                             &t_payload[trans_ind].
                                             sa_attributes[sa_attrib_cnt],
                                             0))
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("ssh_ike_decode_data_attribute returned error"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "Packet does not contain enough data for data "
                            "attribute inside transform payload");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_T,
                                  p, packet_len, ind2 + 4,
                                  "Packet does not contain enough data "
                                  "for attribute inside tranform payload");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(11, negotiation,
                              t_payload[trans_ind].
                              sa_attributes[sa_attrib_cnt].attribute_length,
                              t_payload[trans_ind].
                              sa_attributes[sa_attrib_cnt].attribute,
                              "Decode SA: da[%d], type = %d, value",
                              sa_attrib_cnt,
                              t_payload[trans_ind].
                              sa_attributes[sa_attrib_cnt].attribute_type);
          ind2 += attr_len;
          sa_attrib_cnt++;
        }
      ind += payload_len;
    }
  return 0;
}

/*                                                              shade{0.9}
 * Decode SA-payload                                            shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_sa(SshIkeContext isakmp_context,
                                              SshIkeNegotiation negotiation,
                                              SshIkePayload isakmp_payload,
                                              unsigned char *buffer)
{
  size_t ind, packet_len, payload_len;
  unsigned char *p;
  int prop_cnt, prot_cnt;
  int last_proposal_number, proposal_number;
  SshIkePayloadType next_payload_type;
  SshIkeNotifyMessageType ret;
  SshIkePayloadPProtocol prot;

  SSH_DEBUG(5, ("Start"));
  /* Check length */
  if (isakmp_payload->payload_length < 8)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet does not contain enough data for generic SA "
                    "payload header");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          buffer, isakmp_payload->payload_length,
                          8,
                          "Packet does not contain enough data for "
                          "generic SA payload header");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  isakmp_payload->pl.sa.doi = SSH_IKE_GET32(buffer);
  if (isakmp_payload->pl.sa.doi != SSH_IKE_DOI_IPSEC &&
      isakmp_payload->pl.sa.doi != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid doi = %d, should be %d or 0",
                                     isakmp_payload->pl.sa.doi,
                                     SSH_IKE_DOI_IPSEC));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                    "SA payload contains invalid DOI number");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          buffer,
                          isakmp_payload->payload_length, 4,
                          "Invalid DOI value, should be 0 or 1");
      return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
    }
  /* Doi specific */
  isakmp_payload->pl.sa.situation.situation_flags = SSH_IKE_GET32(buffer + 4);
  SSH_IKE_DEBUG_DECODE(9, negotiation,
                "Decode SA: doi = %d, sit = 0x%x",
                isakmp_payload->pl.sa.doi,
                (int) isakmp_payload->pl.sa.situation.situation_flags);

  if (isakmp_payload->pl.sa.doi == 0)
    {
      if (isakmp_payload->pl.sa.situation.situation_flags != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Warning Invalid situation = %x != 0, when doi == 0",
                         (int) isakmp_payload->pl.sa.situation.
                         situation_flags));
        }
    }
  else
    {
      if (!(isakmp_payload->pl.sa.situation.situation_flags &
            SSH_IKE_SIT_IDENTITY_ONLY))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Warning Invalid situation = %x, identity "
                         "only missing",
                         (int) isakmp_payload->pl.sa.situation.
                         situation_flags));
        }
    }
  ind = 8;
  if (isakmp_payload->pl.sa.situation.situation_flags & SSH_IKE_SIT_SECRECY ||
      isakmp_payload->pl.sa.situation.situation_flags & SSH_IKE_SIT_INTEGRITY)
    {
      if (isakmp_payload->payload_length < 12)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                         isakmp_payload->payload_length, 12));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "SA payload does not contain enough data for "
                        "situation");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                              buffer, isakmp_payload->payload_length,
                              12,
                              "Packet does not contain enough data for "
                              "situation");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }
      isakmp_payload->pl.sa.situation.labeled_domain_identifier =
        SSH_IKE_GET32(buffer + ind);
      ind += 4;
      SSH_IKE_DEBUG_DECODE(9, negotiation,
                                    "labeled domain identifier = %d (0x%x)",
                                    (int) isakmp_payload->pl.sa.situation.
                                    labeled_domain_identifier,
                                    (int) isakmp_payload->pl.sa.situation.
                                    labeled_domain_identifier);
      if (isakmp_payload->pl.sa.situation.situation_flags &
          SSH_IKE_SIT_SECRECY)
        {
          if (isakmp_payload->payload_length < ind + 4)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind + 4));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data for "
                            "secrecy length");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind + 4,
                                  "Packet does not contain enough data for "
                                  "secrecy length");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          isakmp_payload->pl.sa.situation.secrecy_level_length =
            SSH_IKE_GET16(buffer + ind);
          ind += 2;
          if (SSH_IKE_GET16(buffer + ind) != 0)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Reserved secr level len not 0"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Secrecy level length reserved not zero in SA "
                            "payload");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Secrecy level length reserved not 0");
              return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
            }
          ind += 2;
          isakmp_payload->pl.sa.situation.secrecy_level_data = buffer + ind;
          ind += isakmp_payload->pl.sa.situation.secrecy_level_length;
          if (ind % 4 != 0)
            ind = (ind | 0x3) + 1;
          if (isakmp_payload->payload_length < ind + 4)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind + 4));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data "
                            "for secrecy category bitmap length");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind + 4,
                                  "Packet does not contain enough data for "
                                  "secrecy category bitmap length");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          isakmp_payload->pl.sa.situation.secrecy_category_bitmap_length =
            SSH_IKE_GET16(buffer + ind);
          ind += 2;
          if (SSH_IKE_GET16(buffer + ind) != 0)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Reserved secr cat bit len not 0"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Secrecy category bitmap length reserved "
                            "not zero in SA payload");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Secrecy category bitmap length "
                                  "reserved not 0");
              return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
            }
          ind += 2;
          isakmp_payload->pl.sa.situation.secrecy_category_bitmap_data =
            buffer + ind;
          ind += (isakmp_payload->pl.sa.situation
                  .secrecy_category_bitmap_length + 7) / 8;
          if (ind % 4 != 0)
            ind = (ind | 0x3) + 1;
          if (isakmp_payload->payload_length < ind)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data for "
                            "secrecy category bitmap");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Packet does not contain enough data for "
                                  "secrecy category bitmap");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Secrecy level",
                               isakmp_payload->pl.sa.situation.
                               secrecy_level_length,
                              isakmp_payload->pl.sa.situation.
                               secrecy_level_data);
          SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Secrecy bitmap",
                               isakmp_payload->pl.sa.situation.
                               secrecy_category_bitmap_length,
                               isakmp_payload->pl.sa.situation.
                               secrecy_category_bitmap_data);
        }
      if (isakmp_payload->pl.sa.situation.situation_flags &
          SSH_IKE_SIT_INTEGRITY)
        {
          if (isakmp_payload->payload_length < ind + 4)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind + 4));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data "
                            "for integrity length");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind + 4,
                                  "Packet does not contain enough data for "
                                  "integrity length");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          isakmp_payload->pl.sa.situation.integrity_level_length =
            SSH_IKE_GET16(buffer + ind);
          ind += 2;
          if (SSH_IKE_GET16(buffer + ind) != 0)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Reserved incr lvl len not 0"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Integrity level length reserved not "
                            "zero in SA payload");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Integrity level length reserved not 0");
              return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
            }
          ind += 2;
          isakmp_payload->pl.sa.situation.integrity_level_data =
            buffer + ind;
          ind += isakmp_payload->pl.sa.situation.integrity_level_length;
          if (ind % 4 != 0)
            ind = (ind | 0x3) + 1;
          if (isakmp_payload->payload_length < ind + 4)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind + 4));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data for "
                            "integrity category bitmap length");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind + 4,
                                  "Packet does not contain enough data for "
                                  "integrity category bitmap length");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          isakmp_payload->pl.sa.situation.integrity_category_bitmap_length =
            SSH_IKE_GET16(buffer + ind);
          ind += 2;
          if (SSH_IKE_GET16(buffer + ind) != 0)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Reserved incr cat bit len not 0"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Integrity category bitmap length reserved "
                            "not zero in SA payload");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Integrity category bitmap length "
                                  "reserved not 0");
              return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
            }
          ind += 2;
          isakmp_payload->pl.sa.situation.integrity_category_bitmap_data =
            buffer + ind;
          ind += (isakmp_payload->pl.sa.situation
                  .integrity_category_bitmap_length + 7)/ 8;
          if (ind % 4 != 0)
            ind = (ind | 0x3) + 1;
          if (isakmp_payload->payload_length < ind)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                             isakmp_payload->payload_length,
                                             ind));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                            "SA payload does not contain enough data for "
                            "integerity category bitmap");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                                  buffer, isakmp_payload->payload_length,
                                  ind,
                                  "Packet does not contain enough data for "
                                  "integerity category bitmap");
              return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
            }
          SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Integrity level",
                               isakmp_payload->pl.sa.situation.
                               integrity_level_length,
                               isakmp_payload->pl.sa.situation.
                               integrity_level_data);
          SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Integrity bitmap",
                               isakmp_payload->pl.sa.situation.
                               integrity_category_bitmap_length,
                               isakmp_payload->pl.sa.situation.
                               integrity_category_bitmap_data);
        }
    }
  p = buffer + ind;
  packet_len = isakmp_payload->payload_length - ind;
  next_payload_type = SSH_IKE_PAYLOAD_TYPE_P;
  ind = 0;
  prop_cnt = 1;
  if (packet_len < ind + 8)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     packet_len, ind + 8));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet does not contain enough data for "
                    "proposal payload generic header");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                          p, packet_len, ind + 8,
                          "Packet does not contain enough data for "
                          "proposal payload generic header");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }
  last_proposal_number = SSH_IKE_GET8(p + ind + 4);
  while (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      if (packet_len < ind + 8)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                         packet_len, ind + 8));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Packet does not contain enough data for "
                        "proposal payload generic header");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                              p, packet_len, ind + 8,
                              "Packet does not contain enough data for "
                              "proposal payload generic header");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }

      next_payload_type = SSH_IKE_GET8(p + ind);
      if (next_payload_type != SSH_IKE_PAYLOAD_TYPE_P &&
          next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid payload type = %d",
                                         next_payload_type));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                        "Invalid payload type in SA payload");
          SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                              p, packet_len, ind,
              "Next payload inside SA payload must be P or NONE");
          return SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE;
        }

      if (SSH_IKE_GET8(p + ind + 1) != 0)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Reserved 1 not 0"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                        "Generic payload header reserved not zero in "
                        "proposal payload");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                              p, packet_len, ind + 1,
                              "Integrity category bitmap length "
                              "reserved not 0");
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }

      payload_len = SSH_IKE_GET16(p + ind + 2);
      if (payload_len < 4)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                         payload_len, ind + 4));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Payload does not contain enough data for "
                        "proposal payload generic header");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                              p, packet_len, ind + 2,
                              "Packet does not contain enough data for "
                              "proposal payload generic header");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }

      if (packet_len < ind + payload_len)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                         packet_len, ind + payload_len));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Payload length exceeds packet boundary");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                              p, packet_len, ind + 2,
                              "Payload contains more data than packet can "
                              "accommodate");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }

      proposal_number = SSH_IKE_GET8(p + ind + 4);
      if (proposal_number != last_proposal_number)
        {
          prop_cnt++;
          if (proposal_number < last_proposal_number)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Invalid proposal number = %d, should be > %d",
                             proposal_number, last_proposal_number));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX,
                            "Proposal numbers are not monotonically "
                            "increasing");
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                                  p, packet_len, ind + 4,
                                  "Proposal numbers are not monotonically "
                                  "increasing");
              return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
            }
          last_proposal_number = proposal_number;
        }
      ind += payload_len;
    }
  SSH_DEBUG(7, ("Found %d proposals", prop_cnt));

  isakmp_payload->pl.sa.proposals =
    ssh_calloc(prop_cnt, sizeof(struct SshIkePayloadPRec));
  if (isakmp_payload->pl.sa.proposals == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  isakmp_payload->pl.sa.number_of_proposals = prop_cnt;

  next_payload_type = SSH_IKE_PAYLOAD_TYPE_P;
  ind = 0;
  prop_cnt = 0;
  prot_cnt = 0;
  last_proposal_number = SSH_IKE_GET8(p + ind + 4);
  while (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      next_payload_type = SSH_IKE_GET8(p + ind);
      payload_len = SSH_IKE_GET16(p + ind + 2);
      proposal_number = SSH_IKE_GET8(p + ind + 4);
      if (proposal_number != last_proposal_number)
        {
          isakmp_payload->pl.sa.proposals[prop_cnt].protocols =
            ssh_calloc(prot_cnt, sizeof(struct SshIkePayloadPProtocolRec));
          if (isakmp_payload->pl.sa.proposals[prop_cnt].protocols == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          isakmp_payload->pl.sa.proposals[prop_cnt].number_of_protocols =
            prot_cnt;

          isakmp_payload->pl.sa.proposals[prop_cnt].proposal_number =
            last_proposal_number;
          prop_cnt++;
          last_proposal_number = proposal_number;
          prot_cnt = 0;
        }
      prot_cnt++;
      ind += payload_len;
    }


  /* Allocate data for last entry */
  isakmp_payload->pl.sa.proposals[prop_cnt].protocols =
    ssh_calloc(prot_cnt, sizeof(struct SshIkePayloadPProtocolRec));
  if (isakmp_payload->pl.sa.proposals[prop_cnt].protocols == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  isakmp_payload->pl.sa.proposals[prop_cnt].number_of_protocols =
    prot_cnt;

  isakmp_payload->pl.sa.proposals[prop_cnt].proposal_number =
    last_proposal_number;

  next_payload_type = SSH_IKE_PAYLOAD_TYPE_P;
  ind = 0;
  prop_cnt = 0;
  prot_cnt = 0;
  last_proposal_number = SSH_IKE_GET8(p + ind + 4);
  while (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      next_payload_type = SSH_IKE_GET8(p + ind);
      payload_len = SSH_IKE_GET16(p + ind + 2);
      proposal_number = SSH_IKE_GET8(p + ind + 4);
      if (proposal_number != last_proposal_number)
        {
          prop_cnt++;
          last_proposal_number = proposal_number;
          prot_cnt = 0;
        }
      prot = &isakmp_payload->pl.sa.proposals[prop_cnt].protocols[prot_cnt];
      prot->protocol_id = SSH_IKE_GET8(p + ind + 5);
      prot->spi_size = SSH_IKE_GET8(p + ind + 6);
      if (payload_len < SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN + 4 +
          prot->spi_size)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                         payload_len,
                                         SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN +
                                         4 + prot->spi_size));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Payload does not contain enough data for "
                        "spi data");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_P,
                              p, packet_len, ind + 2,
                              "Packet does not contain enough data for "
                              "spi data");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }
      prot->number_of_transforms = SSH_IKE_GET8(p + ind + 7);
      prot->spi = p + ind + 8;
      /* Should the spi_size be padded to 32 bit? */
      SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(9, negotiation,
                                  prot->spi_size, prot->spi,
                                  "Decode SA: Proposal[%d] = %d "
                                  ".protocol[%d] = %d, # transforms = %d, "
                                  "spi",
                                  prop_cnt, proposal_number,
                                  prot_cnt, prot->protocol_id,
                                  prot->number_of_transforms);

      prot->transforms =
        ssh_calloc(prot->number_of_transforms,
                   sizeof(struct SshIkePayloadTRec));
      if (prot->transforms == NULL)
        {
          prot->number_of_transforms = 0;
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      ret =
        ike_decode_payload_t(isakmp_context, negotiation,
                             prot->transforms,
                             p + ind + prot->spi_size +
                             SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN + 4,
                             payload_len - SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN
                             - 4 - prot->spi_size,
                             prot->number_of_transforms);
      if (ret != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ike_decode_payload_t returned error = %d",
                         ret));
          return ret;
        }
      prot_cnt++;
      ind += payload_len;
    }
  return 0;
}

/*                                                              shade{0.9}
 * Decode Key exchange-payload                                  shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_ke(SshIkeContext isakmp_context,
                                              SshIkeNegotiation negotiation,
                                              SshIkePayload isakmp_payload,
                                              unsigned char *buffer)
{
  isakmp_payload->pl.ke.key_exchange_data_len = isakmp_payload->payload_length;
  isakmp_payload->pl.ke.key_exchange_data = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode KE: ke",
                       isakmp_payload->pl.ke.key_exchange_data_len,
                       isakmp_payload->pl.ke.key_exchange_data);
  return 0;
}

/*                                                              shade{0.9}
 * Decode identity-payload                                      shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_id(SshIkeContext isakmp_context,
                                              SshIkeNegotiation negotiation,
                                              SshIkePayload isakmp_payload,
                                              unsigned char *buffer)
{
  if (isakmp_payload->payload_length < 4)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 4));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "ID payload does not contain enough data for fixed data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                          buffer, isakmp_payload->payload_length, 4,
                          "Packet does not contain enough data for "
                          "ID payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  isakmp_payload->pl.id.raw_id_packet = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode ID: packet",
                       isakmp_payload->payload_length,
                       isakmp_payload->pl.id.raw_id_packet);
  return 0;
}

#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * Decode certificate-payload                                   shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_cert(SshIkeContext isakmp_context,
                                                SshIkeNegotiation negotiation,
                                                SshIkePayload isakmp_payload,
                                                unsigned char *buffer)
{
  /* Check length */
  if (isakmp_payload->payload_length < 1)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 1));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "CERT payload does not contain enough data for fixed "
                    "data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_CERT,
                          buffer, isakmp_payload->payload_length, 1,
                          "Packet does not contain enough data for "
                          "CERT payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  isakmp_payload->pl.cert.cert_encoding = SSH_IKE_GET8(buffer);
  /* Should we pad to 4 bytes here? */
  isakmp_payload->pl.cert.certificate_data_len =
    isakmp_payload->payload_length - 1;
  isakmp_payload->pl.cert.certificate_data = buffer + 1;

  SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(9, negotiation,
                              isakmp_payload->pl.cert.certificate_data_len,
                              isakmp_payload->pl.cert.certificate_data,
                              "Decode CERT: encoding = %d, data",
                              isakmp_payload->pl.cert.cert_encoding);
  switch (isakmp_payload->pl.cert.cert_encoding)
    {
    case SSH_IKE_CERTIFICATE_ENCODING_NONE:
    case SSH_IKE_CERTIFICATE_ENCODING_PKCS7:
    case SSH_IKE_CERTIFICATE_ENCODING_PGP:
    case SSH_IKE_CERTIFICATE_ENCODING_DNS:
    case SSH_IKE_CERTIFICATE_ENCODING_X509_SIG:
    case SSH_IKE_CERTIFICATE_ENCODING_X509_KE:
    case SSH_IKE_CERTIFICATE_ENCODING_KERBEROS:
    case SSH_IKE_CERTIFICATE_ENCODING_CRL:
    case SSH_IKE_CERTIFICATE_ENCODING_ARL:
    case SSH_IKE_CERTIFICATE_ENCODING_SPKI:
    case SSH_IKE_CERTIFICATE_ENCODING_X509_ATTR:
      /* Should we should return SSH_IKE_NOTIFY_MESSAGE_INVALID_CERT_ENCODING
         for those values we dont support */
      ; /* For osf/alpha cc */
    break;
    }
  return 0;
}

/*                                                              shade{0.9}
 * Decode certificate request-payload                           shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_cr(SshIkeContext isakmp_context,
                                              SshIkeNegotiation negotiation,
                                              SshIkePayload isakmp_payload,
                                              unsigned char *buffer)
{
  size_t len;

  if (negotiation != NULL &&
      negotiation->ed->compat_flags & SSH_IKE_FLAGS_IGNORE_CR_PAYLOADS)
    return 0;

  /* Check length */
  if (isakmp_payload->payload_length < 1)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 1));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Certificate request payload does not "
                    "contain enough data for fixed data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_CR,
                          buffer, isakmp_payload->payload_length, 1,
                          "Packet does not contain enough data for "
                          "CR payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  len = 0;
  isakmp_payload->pl.cr.certificate_type = buffer[len++];
  isakmp_payload->pl.cr.certificate_authority = buffer + 1;
  isakmp_payload->pl.cr.certificate_authority_len =
    isakmp_payload->payload_length - 1;
  SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(9, negotiation,
                              isakmp_payload->pl.cr.
                              certificate_authority_len,
                              isakmp_payload->pl.cr.certificate_authority,
                              "Decode CR: new, type = %d, value",
                              isakmp_payload->pl.cr.certificate_type);
  return 0;
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/*                                                              shade{0.9}
 * Decode hash-payload                                          shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_hash(SshIkeContext isakmp_context,
                                                SshIkeNegotiation negotiation,
                                                SshIkePayload isakmp_payload,
                                                unsigned char *buffer)
{
  isakmp_payload->pl.hash.hash_data = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode HASH: hash",
                       isakmp_payload->payload_length,
                       isakmp_payload->pl.hash.hash_data);
  return 0;
}

#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * Decode signature-payload                                     shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_sig(SshIkeContext isakmp_context,
                                               SshIkeNegotiation negotiation,
                                               SshIkePayload isakmp_payload,
                                               unsigned char *buffer)
{
  isakmp_payload->pl.sig.signature_data = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode SIG: sig",
                       isakmp_payload->payload_length,
                       isakmp_payload->pl.sig.signature_data);
  return 0;
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/*                                                              shade{0.9}
 * Decode nonce-payload                                         shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_nonce(SshIkeContext isakmp_context,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkePayload isakmp_payload,
                                                 unsigned char *buffer)
{
  isakmp_payload->pl.nonce.raw_nonce_packet = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode NONCE: nonce",
                       isakmp_payload->payload_length,
                       isakmp_payload->pl.nonce.raw_nonce_packet);
  return 0;
}

/*                                                              shade{0.9}
 * Decode notification-payload                                  shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_n(SshIkeContext isakmp_context,
                                             SshIkeNegotiation negotiation,
                                             SshIkePayload isakmp_payload,
                                             unsigned char *buffer)
{
  /* Check length */
  if (isakmp_payload->payload_length < 8)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Notify payload does not contain enough data for fixed "
                    "data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                          buffer, isakmp_payload->payload_length, 8,
                          "Packet does not contain enough data for "
                          "N payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  isakmp_payload->pl.n.doi = SSH_IKE_GET32(buffer);
  /* Doi specific */
  if (isakmp_payload->pl.n.doi != SSH_IKE_DOI_IPSEC &&
      isakmp_payload->pl.n.doi != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid doi = %d, should be = %d or 0",
                                     isakmp_payload->pl.n.doi,
                                     SSH_IKE_DOI_IPSEC));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                    "Invalid DOI in notification payload");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                          buffer,
                          isakmp_payload->payload_length, 4,
                          "Invalid DOI value, should be 0 or 1");
      return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
    }
  isakmp_payload->pl.n.protocol_id = SSH_IKE_GET8(buffer + 4);
  isakmp_payload->pl.n.spi_size = SSH_IKE_GET8(buffer + 5);
  isakmp_payload->pl.n.notify_message_type = SSH_IKE_GET16(buffer + 6);
  if (isakmp_payload->payload_length < 8 + isakmp_payload->pl.n.spi_size)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8 +
                                     isakmp_payload->pl.n.spi_size));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Notify payload does not contain enough data for spi");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                          buffer, isakmp_payload->payload_length,
                          8 + isakmp_payload->pl.n.spi_size,
                          "Packet does not contain enough data for "
                          "N payload SPI");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }
  isakmp_payload->pl.n.spi = buffer + 8;
  /* Should the spi be padded to 32 bit? */
  isakmp_payload->pl.n.notification_data = buffer + 8 +
    isakmp_payload->pl.n.spi_size;
  isakmp_payload->pl.n.notification_data_size =
    isakmp_payload->payload_length - 8 - isakmp_payload->pl.n.spi_size;
  SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(9, negotiation,
                              isakmp_payload->pl.n.spi_size,
                              isakmp_payload->pl.n.spi,
                              "Decode N: doi = %d, proto = %d, "
                              "type = %d, spi",
                              isakmp_payload->pl.n.doi,
                              isakmp_payload->pl.n.protocol_id,
                              isakmp_payload->pl.n.notify_message_type);
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode N: data",
                       isakmp_payload->pl.n.notification_data_size,
                       isakmp_payload->pl.n.notification_data);
  return 0;
}

/*                                                              shade{0.9}
 * Decode delete-payload                                        shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_d(SshIkeContext isakmp_context,
                                             SshIkeNegotiation negotiation,
                                             SshIkePayload isakmp_payload,
                                             unsigned char *buffer)
{
  int i;

  /* Check length */
  if (isakmp_payload->payload_length < 8)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Delete payload does not contain enough data for fixed "
                    "data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                          buffer, isakmp_payload->payload_length, 8,
                          "Packet does not contain enough data for "
                          "D payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  isakmp_payload->pl.d.doi = SSH_IKE_GET32(buffer);
  /* Doi specific */
  if (isakmp_payload->pl.d.doi != SSH_IKE_DOI_IPSEC &&
      isakmp_payload->pl.d.doi != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid doi = %d, should be = %d or 0",
                                     isakmp_payload->pl.n.doi,
                                     SSH_IKE_DOI_IPSEC));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                    "Invalid DOI in delete payload");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                          buffer,
                          isakmp_payload->payload_length, 4,
                          "Invalid DOI value, should be 0 or 1");
      return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
    }
  isakmp_payload->pl.d.protocol_id = SSH_IKE_GET8(buffer + 4);
  isakmp_payload->pl.d.spi_size = SSH_IKE_GET8(buffer + 5);
  isakmp_payload->pl.d.number_of_spis = SSH_IKE_GET16(buffer + 6);

  if (isakmp_payload->payload_length <
      (8 +
       (isakmp_payload->pl.d.spi_size * isakmp_payload->pl.d.number_of_spis)))
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8 +
                                     isakmp_payload->pl.d.spi_size *
                                     isakmp_payload->pl.d.number_of_spis));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Delete payload does not contain enough data for spi "
                    "values");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                          buffer, isakmp_payload->payload_length,
                          8 + isakmp_payload->pl.d.spi_size *
                          isakmp_payload->pl.d.number_of_spis,
                          "Packet does not contain enough data for "
                          "D payload SPI array");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  if (isakmp_payload->pl.d.number_of_spis > (SSH_IKE_MAX_PACKET_LEN / 16))
    {
      SSH_IKE_DEBUG(3, negotiation, ("Long packet : %d < %d",
                                     isakmp_payload->payload_length, 8 +
                                     isakmp_payload->pl.d.spi_size *
                                     isakmp_payload->pl.d.number_of_spis));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Delete payload contains too many spis");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                          buffer, isakmp_payload->payload_length,
                          8 + isakmp_payload->pl.d.spi_size *
                          isakmp_payload->pl.d.number_of_spis,
                          "Delete payload contains too many spis");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  SSH_IKE_DEBUG_DECODE(9, negotiation,
                "Decode D: doi = %d, proto = %d, # spis = %d",
                isakmp_payload->pl.d.doi, isakmp_payload->pl.d.protocol_id,
                isakmp_payload->pl.d.number_of_spis);
  isakmp_payload->pl.d.spis = ssh_calloc(isakmp_payload->pl.d.number_of_spis,
                                         sizeof(unsigned char *));
  if (isakmp_payload->pl.d.spis == NULL)
    {
      isakmp_payload->pl.d.number_of_spis = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Should each spi size be padded to 32 bit? */
  for (i = 0; i < isakmp_payload->pl.d.number_of_spis; i++)
    {
      isakmp_payload->pl.d.spis[i] = buffer + 8 +
        isakmp_payload->pl.d.spi_size * i;
      SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(11, negotiation,
                                  isakmp_payload->pl.d.spi_size,
                                  isakmp_payload->pl.d.spis[i],
                                  "Decode D: spi[%d]", i);
    }
  return 0;
}


/*                                                              shade{0.9}
 * Decode vendor ID-payload                                     shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_vid(SshIkeContext isakmp_context,
                                               SshIkeNegotiation negotiation,
                                               SshIkePayload isakmp_payload,
                                               unsigned char *buffer)
{
  isakmp_payload->pl.vid.vid_data = buffer;
  SSH_IKE_DEBUG_BUFFER_DECODE(9, negotiation, "Decode VID: data",
                       isakmp_payload->payload_length,
                       isakmp_payload->pl.vid.vid_data);
  return 0;
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * Decode attribute-payload                                     shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_attr(SshIkeContext isakmp_context,
                                                SshIkeNegotiation negotiation,
                                                SshIkePayload isakmp_payload,
                                                unsigned char *buffer)
{
  int attr_cnt;
  size_t ind, attr_len;

  SSH_DEBUG(5, ("Start"));
  /* Check length */
  if (isakmp_payload->payload_length < 4)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     isakmp_payload->payload_length, 8));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Attribute payload does not contain enough "
                    "data for fixed data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ATTR,
                          buffer, isakmp_payload->payload_length, 4,
                          "Packet does not contain enough data for "
                          "ATTR payload fixed data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }
  isakmp_payload->pl.attr.type = SSH_IKE_GET8(buffer);
  if (SSH_IKE_GET8(buffer + 1) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Reserved not 0"));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                    "Attribute payload reserved not zero");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ATTR,
                          buffer, isakmp_payload->payload_length, 1,
                          "Reserved not 0");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  isakmp_payload->pl.attr.identifier = SSH_IKE_GET16(buffer + 2);

  attr_cnt = 0;
  ind = 4;
  while (ind + 4 <= isakmp_payload->payload_length)
    {
      ind += ssh_ike_decode_data_attribute_size(buffer + ind, 0);
      attr_cnt++;
    }
  if (ind > isakmp_payload->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Data attribute too long len = %d, payload_len = %d",
                     ind, isakmp_payload->payload_length));
    }
  if (ind < isakmp_payload->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Warning junk after last da"));
    }
  isakmp_payload->pl.attr.attributes =
    ssh_calloc(attr_cnt, sizeof(struct SshIkeDataAttributeRec));
  if (isakmp_payload->pl.attr.attributes == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  isakmp_payload->pl.attr.number_of_attributes = attr_cnt;

  SSH_IKE_DEBUG_DECODE(9, negotiation,
                "Decode ATTR: type = %d, identifier = %d, # attrs = %d",
                isakmp_payload->pl.attr.type,
                isakmp_payload->pl.attr.identifier,
                attr_cnt);

  ind = 4;
  attr_cnt = 0;
  while (ind + 4 <= isakmp_payload->payload_length)
    {
      if (!ssh_ike_decode_data_attribute(buffer + ind,
                                         isakmp_payload->payload_length -
                                         ind,
                                         &attr_len,
                                         &(isakmp_payload->pl.attr.
                                           attributes[attr_cnt]),
                                         0))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_ike_decode_data_attribute returned error"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Packet does not contain enough data for data "
                        "attribute inside attribute payload");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ATTR,
                              buffer, isakmp_payload->payload_length, ind + 4,
                              "Packet does not contain enough data for "
                              "attribute inside ATTR payload");
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }
      SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(11, negotiation,
                                  isakmp_payload->pl.attr.
                                  attributes[attr_cnt].attribute_length,
                                  isakmp_payload->pl.attr.
                                  attributes[attr_cnt].attribute,
                                  "Decode ATTR: da[%d], type = %d, value",
                                  attr_cnt,
                                  isakmp_payload->pl.attr.
                                  attributes[attr_cnt].attribute_type);
      ind += attr_len;
      attr_cnt++;
    }
  return 0;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * Decode private payload                                       shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload_prv(SshIkeContext
                                               isakmp_context,
                                               SshIkeNegotiation
                                               negotiation,
                                               SshIkePayload
                                               isakmp_payload,
                                               unsigned char *buffer)
{
  isakmp_payload->pl.prv.data = buffer;
  SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE(9, negotiation,
                              isakmp_payload->payload_length,
                              isakmp_payload->pl.prv.data,
                              "Decode PRV[%d]: data",
                              isakmp_payload->pl.prv.
                              prv_payload_id);
  return 0;
}


/*                                                              shade{0.9}
 * Decode isakmp payload from buffer and fill in the
 * isakmp_payload structure. Return 0 if ok, otherwise
 * return SshIkeNotifyMessageType error.                        shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_payload(SshIkeContext isakmp_context,
                                           SshIkeNegotiation negotiation,
                                           SshIkePayload isakmp_payload,
                                           unsigned char *buffer)
{
  SshIkeNotifyMessageType ret = 0;
  switch (isakmp_payload->type)
    {
    case SSH_IKE_PAYLOAD_TYPE_SA:
      ret = ike_decode_payload_sa(isakmp_context, negotiation, isakmp_payload,
                                  buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_KE:
      ret = ike_decode_payload_ke(isakmp_context, negotiation, isakmp_payload,
                                  buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_ID:
      ret = ike_decode_payload_id(isakmp_context, negotiation, isakmp_payload,
                                  buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_CERT:
#ifdef SSHDIST_IKE_CERT_AUTH
      ret = ike_decode_payload_cert(isakmp_context, negotiation,
                                    isakmp_payload, buffer);
#endif /* SSHDIST_IKE_CERT_AUTH */
      break;
    case SSH_IKE_PAYLOAD_TYPE_CR:
#ifdef SSHDIST_IKE_CERT_AUTH
      ret = ike_decode_payload_cr(isakmp_context, negotiation, isakmp_payload,
                                  buffer);
#endif /* SSHDIST_IKE_CERT_AUTH */
      break;
    case SSH_IKE_PAYLOAD_TYPE_HASH:
      ret = ike_decode_payload_hash(isakmp_context, negotiation,
                                    isakmp_payload, buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_SIG:
#ifdef SSHDIST_IKE_CERT_AUTH
      ret = ike_decode_payload_sig(isakmp_context, negotiation,
                                   isakmp_payload, buffer);
#endif /* SSHDIST_IKE_CERT_AUTH */
      break;
    case SSH_IKE_PAYLOAD_TYPE_NONCE:
      ret = ike_decode_payload_nonce(isakmp_context, negotiation,
                                     isakmp_payload, buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_N:
      ret = ike_decode_payload_n(isakmp_context, negotiation, isakmp_payload,
                                 buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_D:
      ret = ike_decode_payload_d(isakmp_context, negotiation, isakmp_payload,
                                 buffer);
      break;
    case SSH_IKE_PAYLOAD_TYPE_VID:
      ret = ike_decode_payload_vid(isakmp_context, negotiation,
                                   isakmp_payload, buffer);
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_PAYLOAD_TYPE_ATTR:
      ret = ike_decode_payload_attr(isakmp_context, negotiation,
                                    isakmp_payload, buffer);
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case SSH_IKE_PAYLOAD_TYPE_PRV:
      ret = ike_decode_payload_prv(isakmp_context, negotiation,
                                       isakmp_payload, buffer);
      break;
    default:
      ssh_fatal("Internal error in ike_decode_payload, "
                "got invalid packet type: %d", isakmp_payload->type);
      break;
    }
  return ret;
}

/*                                                              shade{0.9}
 * Decode isakmp packet from buffer and allocate and
 * fill in the isakmp_packet structure. If ok, consumes
 * the packet from buffer, otherwise leave packet to
 * buffer. Returns 0 if ok, otherwise return
 * SshIkeNotifyMessageType error. SshBuffer length must
 * be >= 28 (SSH_IKE header). Isakmp_sa must point to
 * SshIkeSA of the exchange.                                    shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_packet(SshIkeContext isakmp_context,
                                          SshIkePacket *isakmp_packet_out,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshBuffer buffer)
{
  size_t len, i, payload_len;
  unsigned char *p;
  SshIkePayloadType first_payload_type, next_payload_type;
  int ind;
  SshIkePayload *ptr = NULL;
  SshIkeNotifyMessageType ret;
  SshIkePacket isakmp_packet;

  SSH_DEBUG(5, ("Start"));
  len = ssh_buffer_len(buffer);
  if (len < SSH_IKE_PACKET_GENERIC_HEADER_LEN)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ike_decode_packet got short packet: %ld",
                                     (unsigned long) len));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet does not contain enough data "
                    "for next generic payload header");
      SSH_IKE_NOTIFY_TEXT(negotiation,
                          "Packet does not contain enough data for "
                          "generic ISAKMP packet header");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  *isakmp_packet_out = NULL;
  isakmp_packet = ssh_calloc(1, sizeof(struct SshIkePacketRec));
  if (isakmp_packet == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  p = ssh_buffer_ptr(buffer);

  SSH_IKE_DEBUG_BUFFER(11, negotiation, "Packet received", len, p);

  /* Fill in the packet structure */
  memcpy(isakmp_packet->cookies.initiator_cookie, p, SSH_IKE_COOKIE_LENGTH);
  memcpy(isakmp_packet->cookies.responder_cookie, p + SSH_IKE_COOKIE_LENGTH,
         SSH_IKE_COOKIE_LENGTH);
  first_payload_type = SSH_IKE_GET8(p + 16);
  isakmp_packet->major_version = SSH_IKE_GET4L(p + 17);
  isakmp_packet->minor_version = SSH_IKE_GET4R(p + 17);
  isakmp_packet->exchange_type = SSH_IKE_GET8(p + 18);
  isakmp_packet->flags = SSH_IKE_GET8(p + 19);
  isakmp_packet->message_id = SSH_IKE_GET32(p + 20);
  isakmp_packet->length = SSH_IKE_GET32(p + 24);

  ike_debug_decode_start(negotiation);

  if (isakmp_sa && negotiation)
    SSH_DEBUG(5,
              ("Start, SA = { %08lx %08lx - %08lx %08lx} / %08lx, nego = %d",
               (unsigned long)
               SSH_IKE_GET32(isakmp_sa->cookies.initiator_cookie),
               (unsigned long)
               SSH_IKE_GET32(isakmp_sa->cookies.initiator_cookie + 4),
               (unsigned long)
               SSH_IKE_GET32(isakmp_sa->cookies.responder_cookie),
                (unsigned long)
               SSH_IKE_GET32(isakmp_sa->cookies.responder_cookie + 4),
               (unsigned long)
               isakmp_packet->message_id, negotiation->negotiation_index));
  else
    SSH_DEBUG(5, ("Start, SA = { NULL } / 0, nego = 0"));

  if (isakmp_packet->length < SSH_IKE_PACKET_GENERIC_HEADER_LEN)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ike_decode_packet got short packet, "
                                     "message length = %ld",
                                     (unsigned long) isakmp_packet->length));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet does not contain enough data "
                    "for generic ISAKMP packet header");
      ssh_free(isakmp_packet);
      SSH_IKE_NOTIFY_TEXT(negotiation,
                          "Packet does not contain enough data for "
                          "generic ISAKMP packet header");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  /* Check for version numbers */
  if (isakmp_packet->major_version != SSH_IKE_MAJOR_VERSION ||
      (isakmp_sa &&
       isakmp_packet->major_version !=
       isakmp_sa->isakmp_negotiation->ike_pm_info->major_version))
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid major version = %d",
                                    isakmp_packet->major_version));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_VERSION,
                "Major version numbers are different");
      ssh_free(isakmp_packet);
      SSH_IKE_NOTIFY_TEXT(negotiation, "Invalid ISAKMP major version number");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_MAJOR_VERSION;
    }
  if (isakmp_packet->minor_version != SSH_IKE_MINOR_VERSION ||
      (isakmp_sa &&
       isakmp_packet->minor_version !=
       isakmp_sa->isakmp_negotiation->ike_pm_info->minor_version))
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid minor version = %d",
                                     isakmp_packet->minor_version));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_VERSION,
                "Minor version numbers are different");
      ssh_free(isakmp_packet);
      SSH_IKE_NOTIFY_TEXT(negotiation, "Invalid ISAKMP minor version number");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_MINOR_VERSION;
    }

  SSH_DEBUG(9, ("first_payload_type:%d.", first_payload_type));

  /* Check next payload field */
  if (first_payload_type == SSH_IKE_PAYLOAD_TYPE_P ||
      first_payload_type == SSH_IKE_PAYLOAD_TYPE_T)
    goto invalid_first_payload;

  if (negotiation &&
      first_payload_type >= SSH_IKE_PAYLOAD_TYPE_MAX)
    {
      switch (negotiation->exchange_type)
        {
        case SSH_IKE_XCHG_TYPE_IP:
        case SSH_IKE_XCHG_TYPE_AGGR:
          if (negotiation->ed->private_payload_phase_1_check &&
              (*negotiation->ed->
               private_payload_phase_1_check)(negotiation->ike_pm_info,
                                              first_payload_type,
                                              negotiation->ed->
                                              private_payload_context))
            goto ok;
          break;
        case SSH_IKE_XCHG_TYPE_QM:
          if (negotiation->ed->private_payload_phase_qm_check &&
              (*negotiation->ed->
               private_payload_phase_qm_check)(negotiation->qm_pm_info,
                                               first_payload_type,
                                               negotiation->ed->
                                               private_payload_context))
            goto ok;
          break;
        case SSH_IKE_XCHG_TYPE_NGM:
          if (negotiation->ed->private_payload_phase_2_check &&
              (*negotiation->ed->
               private_payload_phase_2_check)(negotiation->ngm_pm_info,
                                              first_payload_type,
                                              negotiation->ed->
                                              private_payload_context))
            goto ok;
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_XCHG_TYPE_CFG:
          if (negotiation->ed->private_payload_phase_2_check &&
              (*negotiation->ed->
               private_payload_phase_2_check)(negotiation->cfg_pm_info,
                                              first_payload_type,
                                              negotiation->ed->
                                              private_payload_context))
            goto ok;
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        case SSH_IKE_XCHG_TYPE_INFO:
          if (negotiation->ed->private_payload_phase_2_check &&
              (*negotiation->ed->
               private_payload_phase_2_check)(negotiation->info_pm_info,
                                              first_payload_type,
                                              negotiation->ed->
                                              private_payload_context))
            goto ok;
          break;
        default:
          break;
        }

    invalid_first_payload:
      SSH_IKE_DEBUG(3, negotiation,
                    ("Invalid first payload type = %d", first_payload_type));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                    "Invalid payload type in first payload");
      SSH_IKE_NOTIFY_DATA(negotiation, first_payload_type,
                          NULL, 0, -1,
                          "Invalid first payload value");
      ssh_free(isakmp_packet);
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE;
    }
ok:
  if (negotiation &&
      isakmp_packet->exchange_type != negotiation->exchange_type)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Exchange type changed from previous value, "
                     "old = %d, new = %d",
                     negotiation->exchange_type,
                     isakmp_packet->exchange_type));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_EXCHANGE_TYPE,
                "Exchange type changed during the negotiation");
      ssh_free(isakmp_packet);
      SSH_IKE_NOTIFY_TEXT(negotiation,
                          "Exchange type changed during the negotiation");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_EXCHANGE_TYPE;
    }
  if ((isakmp_packet->flags & ~SSH_IKE_FLAGS_SUPPORTED) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Invalid flags = %08x",
                                     isakmp_packet->flags));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_FLAGS,
                "ISAKMP generic header flags contains unsupported bits");
      SSH_IKE_NOTIFY_TEXT(negotiation, "Invalid flags");
      if (negotiation && negotiation->ed)
        negotiation->ed->invalid_flags =
          (isakmp_packet->flags & ~SSH_IKE_FLAGS_SUPPORTED);
      ssh_free(isakmp_packet);
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_FLAGS;
    }
  /* Message id check is left to the caller. */
  if (isakmp_packet->length > len)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Short packet : %d < %d",
                                     len, isakmp_packet->length));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                "UDP packet does not contain enough data for ISAKMP packet");
      ssh_free(isakmp_packet);
      SSH_IKE_NOTIFY_TEXT(negotiation,
                          "UDP Packet does not contain enough data for "
                          "ISAKMP packet");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }
  if (isakmp_packet->length < len)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Warning, junk after isakmp packet length = %d, "
                     "udp packet length = %d",
                     isakmp_packet->length, len));
      len = isakmp_packet->length;
    }
  isakmp_packet->encoded_packet = ssh_malloc(isakmp_packet->length);
  if (isakmp_packet->encoded_packet == NULL)
    {
      ssh_free(isakmp_packet);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  isakmp_packet->encoded_packet_len = isakmp_packet->length;
  if (isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION)
    {
      SshCryptoStatus cret;

      if (negotiation == NULL || negotiation->ed->decryption_cipher == NULL)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Trying to decrypt, but no decryption context "
                         "initialized"));
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_NO_SA_ESTABLISHED;
        }
      memcpy(isakmp_packet->encoded_packet, p,
             SSH_IKE_PACKET_GENERIC_HEADER_LEN);

      SSH_DEBUG(7, ("Decrypting packet"));

      cret = ssh_cipher_start(negotiation->ed->decryption_cipher);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_start decrypt failed: %.200s",
                         ssh_crypto_status_message(cret)));
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      cret = ssh_cipher_transform(negotiation->ed->decryption_cipher,
                                  isakmp_packet->encoded_packet +
                                  SSH_IKE_PACKET_GENERIC_HEADER_LEN,
                                  p + SSH_IKE_PACKET_GENERIC_HEADER_LEN,
                                  isakmp_packet->length -
                                  SSH_IKE_PACKET_GENERIC_HEADER_LEN);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_cipher_transform decrypt failed: %.200s",
                         ssh_crypto_status_message(cret)));
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      SSH_IKE_DEBUG_BUFFER(11, negotiation, "Decrypted packet",
                           isakmp_packet->length,
                           isakmp_packet->encoded_packet);

      /* Copy the last bytes of the encrypted packet to cipher_iv */
      memcpy(negotiation->ed->cipher_iv,
             p + isakmp_packet->length - negotiation->sa->cipher_iv_len,
             negotiation->sa->cipher_iv_len);
    }
  else
    {
      memcpy(isakmp_packet->encoded_packet, p, isakmp_packet->length);
    }

  /* Skip the isakmp header */
  len -= SSH_IKE_PACKET_GENERIC_HEADER_LEN;
  p = isakmp_packet->encoded_packet + SSH_IKE_PACKET_GENERIC_HEADER_LEN;

  /* Count the number of payload packets */
  i = 0;
  ind = 0;
  next_payload_type = first_payload_type;
  while (i + SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN <= len &&
         next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      next_payload_type = SSH_IKE_GET8(p + i);
      SSH_DEBUG(9, ("next_payload_type:%d.", next_payload_type));
      if (negotiation &&
          next_payload_type >= SSH_IKE_PAYLOAD_TYPE_MAX)
        {
          switch (negotiation->exchange_type)
            {
            case SSH_IKE_XCHG_TYPE_IP:
            case SSH_IKE_XCHG_TYPE_AGGR:
              if (negotiation->ed->private_payload_phase_1_check &&
                  (*negotiation->ed->
                   private_payload_phase_1_check)(negotiation->ike_pm_info,
                                                  next_payload_type,
                                                  negotiation->ed->
                                                  private_payload_context))
                goto ok2;
              break;
            case SSH_IKE_XCHG_TYPE_QM:
              if (negotiation->ed->private_payload_phase_qm_check &&
                  (*negotiation->ed->
                   private_payload_phase_qm_check)(negotiation->qm_pm_info,
                                                   next_payload_type,
                                                   negotiation->ed->
                                                   private_payload_context))
                goto ok2;
              break;
            case SSH_IKE_XCHG_TYPE_NGM:
              if (negotiation->ed->private_payload_phase_2_check &&
                  (*negotiation->ed->
                   private_payload_phase_2_check)(negotiation->ngm_pm_info,
                                                  next_payload_type,
                                                  negotiation->ed->
                                                  private_payload_context))
                goto ok2;
              break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
            case SSH_IKE_XCHG_TYPE_CFG:
              if (negotiation->ed->private_payload_phase_2_check &&
                  (*negotiation->ed->
                   private_payload_phase_2_check)(negotiation->cfg_pm_info,
                                                  next_payload_type,
                                                  negotiation->ed->
                                                  private_payload_context))
                goto ok2;
              break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
            case SSH_IKE_XCHG_TYPE_INFO:
              if (negotiation->ed->private_payload_phase_2_check &&
                  (*negotiation->ed->
                   private_payload_phase_2_check)(negotiation->info_pm_info,
                                                  next_payload_type,
                                                  negotiation->ed->
                                                  private_payload_context))
                goto ok2;
              break;
            default:
              break;
            }
        }
      if (next_payload_type == SSH_IKE_PAYLOAD_TYPE_P ||
          next_payload_type == SSH_IKE_PAYLOAD_TYPE_T ||
          next_payload_type >= SSH_IKE_PAYLOAD_TYPE_MAX)
        {
          payload_len = SSH_IKE_GET16(p + i + 2);
          if (payload_len < 4)
            payload_len = 4;
          if (payload_len > len)
            payload_len = len;

          SSH_IKE_DEBUG(3, negotiation, ("Invalid next payload type = %d",
                                         next_payload_type));
          if (isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION &&
              negotiation &&
              negotiation->ed->auth_method_type ==
              SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY)
            {
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                            "Invalid payload type in encrypted payload "
                            "chain, possibly because of different "
                            "pre-shared keys");
              SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                                  p + i, payload_len, 0,
                                  "Incorrect pre-shared key "
                                  "(Invalid next payload value)");
            }
          else
            {
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD,
                            "Invalid payload type in payload chain");
              SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                                  p + i, payload_len, 0,
                                  "Invalid next payload value");
            }
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_INVALID_PAYLOAD_TYPE;
        }
    ok2:

      if (SSH_IKE_GET8(p + i + 1) != 0)
        {
          payload_len = SSH_IKE_GET16(p + i + 2);
          if (payload_len < 4)
            payload_len = 4;
          if (payload_len > len)
            payload_len = len;

          SSH_IKE_DEBUG(3, negotiation, ("Reserved 1 not 0"));
          if (isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION &&
              negotiation &&
              negotiation->ed->auth_method_type ==
              SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY)
            {
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Generic payload header reserved not zero, "
                            "possibly because of different pre-shared keys");
              SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                                  p + i, payload_len, 1,
                                  "Incorrect pre-shared key "
                                  "(Reserved not 0)");
            }
          else
            {
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_RESERVED_FIELD,
                            "Generic payload header reserved not zero");
              SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                                  p + i, payload_len, 1,
                                  "Reserved not 0");
            }
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
        }
      payload_len = SSH_IKE_GET16(p + i + 2);
      i += payload_len;
      if (payload_len < 4)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Short packet : payload size < 4"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                        "Payload does not contain enough data for "
                        "generic payload header");
          SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                              p, payload_len, 4,
                              "Packet does not contain enough data for "
                              "payload fixed data");
          ssh_free(isakmp_packet->encoded_packet);
          ssh_free(isakmp_packet);
          return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
        }
      ind++;
    }
  if (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Invalid last payload type = %d", next_payload_type));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet does not contain enough data for next payload, "
                    "but next payload type is not zero");
      SSH_IKE_NOTIFY_DATA(negotiation, next_payload_type,
                          NULL, 0, -1,
                          "Packet does not contain enough data for "
                          "last payload");
      ssh_free(isakmp_packet->encoded_packet);
      ssh_free(isakmp_packet);
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  /* Fix the length to correct size */
  isakmp_packet->length = i + SSH_IKE_PACKET_GENERIC_HEADER_LEN;

  if ((isakmp_packet->flags & SSH_IKE_FLAGS_ENCRYPTION)
      && negotiation)
    {
      while (i % negotiation->ed->cipher_block_length != 0)
        i++;
    }
  if (i != len)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Warning, junk after packet len = %d, decoded = %d",
                     len, i));
    }
  if (i > len)
    {
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "Packet length does not agree with the encoded payload "
                    "lengths");
      ssh_free(isakmp_packet->encoded_packet);
      ssh_free(isakmp_packet);
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  /* Allocate payloads structures */
  isakmp_packet->number_of_payload_packets = ind;
  isakmp_packet->number_of_payload_packets_allocated = ind;
  if (ind != 0)
    {
      isakmp_packet->payloads = ssh_calloc(ind, sizeof(SshIkePayload));
      if (isakmp_packet->payloads == NULL)
        {
          isakmp_packet->number_of_payload_packets = 0;
          isakmp_packet->number_of_payload_packets_allocated = 0;
          ike_free_packet(isakmp_packet, 0);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }
    }
  else
    {
      SSH_IKE_DEBUG(3, negotiation, ("No payloads in packet"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No payloads in packet");
      ike_free_packet(isakmp_packet, 0);
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  for (ind = 0; ind < isakmp_packet->number_of_payload_packets; ind++)
    isakmp_packet->payloads[ind] = NULL;

  /* Decode payloads */
  i = 0;
  ind = 0;
  next_payload_type = first_payload_type;
  while (next_payload_type != SSH_IKE_PAYLOAD_TYPE_NONE)
    {
      /* Fill in generic payload header */
      isakmp_packet->payloads[ind] =
        ssh_calloc(1, sizeof(struct SshIkePayloadRec));
      if (isakmp_packet->payloads[ind] == NULL)
        {
          ike_free_packet(isakmp_packet, 0);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      if (next_payload_type >= SSH_IKE_PAYLOAD_TYPE_MAX)
        {
          /* This is private payload, but we have already checked that it is
             ok, so store the information */
          isakmp_packet->payloads[ind]->pl.prv.prv_payload_id =
            next_payload_type;
          next_payload_type = SSH_IKE_PAYLOAD_TYPE_PRV;
        }
      isakmp_packet->payloads[ind]->type = next_payload_type;
      payload_len = SSH_IKE_GET16(p + i + 2);
      isakmp_packet->payloads[ind]->payload_length = payload_len -
        SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN;
      isakmp_packet->payloads[ind]->next_same_payload = NULL;
      isakmp_packet->payloads[ind]->payload_offset = i;
      isakmp_packet->payloads[ind]->payload_start = p + i;
      isakmp_packet->payloads[ind]->func = NULL_FNPTR;

      /* Update first_xx_payload and next_same_payload pointers */
      switch (next_payload_type)
        {
        case SSH_IKE_PAYLOAD_TYPE_SA:
          ptr = &(isakmp_packet->first_sa_payload);
          break;
        case SSH_IKE_PAYLOAD_TYPE_KE:
          ptr = &isakmp_packet->first_ke_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_ID:
          ptr = &isakmp_packet->first_id_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_CERT:
          ptr = &isakmp_packet->first_cert_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_CR:
          ptr = &isakmp_packet->first_cr_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_HASH:
          ptr = &isakmp_packet->first_hash_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_SIG:
          ptr = &isakmp_packet->first_sig_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_NONCE:
          ptr = &isakmp_packet->first_nonce_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_N:
          ptr = &isakmp_packet->first_n_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_D:
          ptr = &isakmp_packet->first_d_payload;
          break;
        case SSH_IKE_PAYLOAD_TYPE_VID:
          ptr = &isakmp_packet->first_vid_payload;
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_PAYLOAD_TYPE_ATTR:
          ptr = &isakmp_packet->first_attr_payload;
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        case SSH_IKE_PAYLOAD_TYPE_PRV:
          ptr = &isakmp_packet->first_private_payload;
          break;
        default:
          ssh_fatal("Internal error in ike_decode_packet, got invalid"
                    " payload type: %d", next_payload_type);
          break;
        }
      while (*ptr != NULL)
        ptr = &((*ptr)->next_same_payload);
      *ptr = isakmp_packet->payloads[ind];

      ret = ike_decode_payload(isakmp_context, negotiation,
                               isakmp_packet->payloads[ind],
                               p + i +
                               SSH_IKE_PAYLOAD_GENERIC_HEADER_LEN);
      if (ret != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ike_decode_payload returned error = %d", ret));
          if (negotiation)
            ike_free_packet(isakmp_packet, negotiation->ed->compat_flags);
          else
            ike_free_packet(isakmp_packet, 0);
          return ret;
        }

      next_payload_type = SSH_IKE_GET8(p + i);
      i += payload_len;
      ind++;
    }
  *isakmp_packet_out = isakmp_packet;

  ike_debug_packet_in(negotiation, isakmp_packet);

  return 0;
}


/*                                                              shade{0.9}
 * ike_decode_id
 * Decode ID payload.                                           shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_id_id(SshIkeContext isakmp_context,
                                         SshIkeNegotiation negotiation,
                                         SshIkePayloadID id,
                                         unsigned char *p,
                                         size_t len)
{
  /* Read general information */
  id->id_type = SSH_IKE_GET8(p);
  id->protocol_id = SSH_IKE_GET8(p + 1);
  id->port_number = SSH_IKE_GET16(p + 2);
  id->identification_len = len - 4;

  /* Find out length of identification data */
  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR: len = 4; break;
    case IPSEC_ID_FQDN:
      id->identification.fqdn = NULL;
      len = id->identification_len;
      break;
    case IPSEC_ID_USER_FQDN:
      id->identification.user_fqdn = NULL;
      len = id->identification_len;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET: len = 8; break;
    case IPSEC_ID_IPV6_ADDR: len = 16; break;
    case IPSEC_ID_IPV6_ADDR_SUBNET: len = 32; break;
    case IPSEC_ID_IPV4_ADDR_RANGE: len = 8; break;
    case IPSEC_ID_IPV6_ADDR_RANGE: len = 32; break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      id->identification.asn1_data = NULL;
      len = id->identification_len;
      break;
    case IPSEC_ID_KEY_ID:
      id->identification.key_id = NULL;
      len = id->identification_len;
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        SshIkeIpsecIdentificationType id_type;
        size_t rest, payload_len;
        unsigned char *q;
        Boolean ok;
        int cnt;

        rest = id->identification_len;
        q = p + 4;
        cnt = 0;
        while (rest > 4)
          {
            /* Ignore Next Payload. */
            /* Ignore RESERVED */
            payload_len = SSH_IKE_GET16(q + 2);
            cnt++;
            if (rest < payload_len)
              {
                ssh_ike_audit(negotiation,
                              SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                              "ID payload does not contain enough data "
                              "for identification data");
                SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                    p, len, id->identification_len,
                                    "Packet does not contain enough data for "
                                    "ID payload data");
                return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
              }
            id_type = SSH_IKE_GET8(q + 4);
            ok = FALSE;
            switch (id_type)
              {
              case IPSEC_ID_IPV4_ADDR:
              case IPSEC_ID_FQDN:
              case IPSEC_ID_USER_FQDN:
              case IPSEC_ID_IPV4_ADDR_SUBNET:
              case IPSEC_ID_IPV6_ADDR:
              case IPSEC_ID_IPV6_ADDR_SUBNET:
              case IPSEC_ID_IPV4_ADDR_RANGE:
              case IPSEC_ID_IPV6_ADDR_RANGE:
              case IPSEC_ID_DER_ASN1_DN:
              case IPSEC_ID_DER_ASN1_GN:
              case IPSEC_ID_KEY_ID:
                ok = TRUE;
                break;
#ifdef SSHDIST_IKE_ID_LIST
              case IPSEC_ID_LIST:
                SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                    p, len, 0, "Invalid ID_LIST in ID_LIST");
                return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;
#endif /* SSHDIST_IKE_ID_LIST */
              }
            if (!ok)
              {
                SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                    p, len, 0, "Invalid id type in ID_LIST");
                return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;
              }
            rest -= payload_len + 4;
            q += payload_len + 4;
          }
        if (rest != 0)
          {
            ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                          "ID payload does not contain enough data "
                          "for id_list identification data header");
            SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                p, len, id->identification_len,
                                "Packet does not contain enough data for "
                                "ID payload id_list data header");
            return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
          }
        id->identification.id_list_number_of_items = cnt;
        id->identification.id_list_items = NULL;
        len = id->identification_len;
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    default:
      SSH_IKE_DEBUG(3, negotiation, ("Error: unknown ID-type %d,%d,%d,%d",
                                     id->id_type,
                                     id->protocol_id,
                                     id->port_number,
                                     id->identification_len));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                          p, len, 0, "Invalid ID type");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;
    }

  /* Check that there is enough data left */
  if (id->identification_len < len)
    {
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                    "ID payload does not contain enough data "
                    "for identification data");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                          p, len, id->identification_len,
                          "Packet does not contain enough data for "
                          "ID payload data");
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  id->identification_len = len;

  /* Copy data to identification union */
  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      memmove(id->identification.ipv4_addr, p + 4, 4);
      break;
    case IPSEC_ID_FQDN:         /* Note! this is NOT null terminated */
      id->identification.fqdn = p + 4;
      break;
    case IPSEC_ID_USER_FQDN:    /* Note! this is NOT null terminated */
      id->identification.user_fqdn = p + 4;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      memmove(id->identification.ipv4_addr_subnet, p + 4, 4);
      memmove(id->identification.ipv4_addr_netmask, p + 8, 4);
      break;
    case IPSEC_ID_IPV6_ADDR:
      memmove(id->identification.ipv6_addr, p + 4, 16);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      memmove(id->identification.ipv6_addr_subnet, p + 4, 16);
      memmove(id->identification.ipv6_addr_netmask, p + 20, 16);
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      memmove(id->identification.ipv4_addr_range1, p + 4, 4);
      memmove(id->identification.ipv4_addr_range2, p + 8, 4);
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      memmove(id->identification.ipv6_addr_range1, p + 4, 16);
      memmove(id->identification.ipv6_addr_range2, p + 20, 16);
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      id->identification.asn1_data = p + 4;
      break;
    case IPSEC_ID_KEY_ID:
      id->identification.key_id = p + 4;
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        SshIkeNotifyMessageType ret;
        size_t rest, payload_len;
        unsigned char *q;
        int cnt;

        id->identification.id_list_items =
          ssh_calloc(id->identification.id_list_number_of_items,
                     sizeof(struct SshIkePayloadIDRec));
        if (id->identification.id_list_items == NULL)
          {
            id->identification.id_list_number_of_items = 0;
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          }

        rest = id->identification_len;
        q = p + 4;
        for (cnt = 0;
            cnt < id->identification.id_list_number_of_items;
            cnt++)
          {
            /* Ignore Next Payload. */
            /* Ignore RESERVED */
            payload_len = SSH_IKE_GET16(q + 2);
            ret = ike_decode_id_id(isakmp_context, negotiation,
                                   &(id->identification.id_list_items[cnt]),
                                   q + 4, payload_len);
            if (ret != 0)
              return ret;
            rest -= payload_len + 4;
            q += payload_len + 4;
          }
        id->identification_len = 0;
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    }

#ifdef DEBUG_LIGHT
  {
    char buffer[255];
    ssh_ike_id_to_string(buffer, sizeof(buffer), id);

    SSH_IKE_DEBUG_DECODE(9, negotiation, "Decoded ID = %s", buffer);
  }
#endif
  return 0;
}

/*                                                              shade{0.9}
 * ike_decode_id
 * Decode ID payload.                                           shade{1.0}
 */
SshIkeNotifyMessageType ike_decode_id(SshIkeContext isakmp_context,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayload id,
                                      unsigned char *p,
                                      size_t len)
{
  return ike_decode_id_id(isakmp_context, negotiation, &(id->pl.id), p, len);
}

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshIkePacketEncode"

/*                                                              shade{0.9}
 * isakmp_encode_id_id
 * Encode ID payload. Always assigns into 'return_p'.           shade{1.0}
 */
SshIkeNotifyMessageType ike_encode_id_id(SshIkeContext isakmp_context,
                                         SshIkeNegotiation negotiation,
                                         SshIkePayloadID id,
                                         unsigned char **return_p,
                                         size_t *return_len)
{
  SshBuffer buffer;
  size_t len;

#ifdef DEBUG_LIGHT
  {
    char buf[255];
    ssh_ike_id_to_string(buf, sizeof(buf), id);
    SSH_IKE_DEBUG_ENCODE(9, negotiation, "Encoding ID = %s", buf);
  }
#endif

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      *return_p = NULL;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Encode id packet to raw format ready for encryption */
  len = 0;
  APPEND_CHAR(buffer, id->id_type, len);
  APPEND_CHAR(buffer, id->protocol_id, len);
  APPEND_INT16(buffer, id->port_number, len);
  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      APPEND_PTR(buffer, id->identification.ipv4_addr, 4, len);
      break;
    case IPSEC_ID_FQDN:
      APPEND_PTR(buffer, id->identification.fqdn,
                 id->identification_len, len);
      break;
    case IPSEC_ID_USER_FQDN:
      APPEND_PTR(buffer, id->identification.user_fqdn,
                 id->identification_len, len);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      APPEND_PTR(buffer, id->identification.ipv4_addr_subnet, 4, len);
      APPEND_PTR(buffer, id->identification.ipv4_addr_netmask, 4, len);
      break;
    case IPSEC_ID_IPV6_ADDR:
      APPEND_PTR(buffer, id->identification.ipv6_addr, 16, len);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      APPEND_PTR(buffer, id->identification.ipv6_addr_subnet, 16, len);
      APPEND_PTR(buffer, id->identification.ipv6_addr_netmask, 16, len);
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      APPEND_PTR(buffer, id->identification.ipv4_addr_range1, 4, len);
      APPEND_PTR(buffer, id->identification.ipv4_addr_range2, 4, len);
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      APPEND_PTR(buffer, id->identification.ipv6_addr_range1, 16, len);
      APPEND_PTR(buffer, id->identification.ipv6_addr_range2, 16, len);
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      APPEND_PTR(buffer, id->identification.asn1_data,
                 id->identification_len, len);
      break;
    case IPSEC_ID_KEY_ID:
      APPEND_PTR(buffer, id->identification.key_id,
                 id->identification_len, len);
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        SshIkeNotifyMessageType ret;
        unsigned char *payload;
        size_t payload_len;
        int cnt;

        for (cnt = 0;
            cnt < id->identification.id_list_number_of_items;
            cnt++)
          {
            ret = ike_encode_id_id(isakmp_context, negotiation,
                                   &(id->identification.id_list_items[cnt]),
                                   &payload, &payload_len);
            if (ret != 0)
              {
                ssh_buffer_free(buffer);
                return ret;
              }
            if (cnt != id->identification.id_list_number_of_items - 1)
              APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_ID, len);
            else
              APPEND_CHAR(buffer, SSH_IKE_PAYLOAD_TYPE_NONE, len);
            APPEND_CHAR(buffer, 0, len);
            APPEND_INT16(buffer, payload_len, len);
            APPEND_PTR(buffer, payload, payload_len, len);
            ssh_free(payload);
          }
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    }

  *return_len = ssh_buffer_len(buffer);
  *return_p = ssh_memdup(ssh_buffer_ptr(buffer), *return_len);
  if (*return_p == NULL)
    {
      ssh_buffer_free(buffer);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  ssh_buffer_free(buffer);
  return 0;

 error:
  *return_p = NULL;
  ssh_buffer_free(buffer);
  return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

 error_payload_malformed:
  *return_p = NULL;
  ssh_buffer_free(buffer);
  return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
}

/*                                                              shade{0.9}
 * isakmp_encode_id
 * Encode ID payload to generic payload.                        shade{1.0}
 */
SshIkeNotifyMessageType ike_encode_id(SshIkeContext isakmp_context,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayload id,
                                      unsigned char **return_p,
                                      size_t *return_len)
{
  return ike_encode_id_id(isakmp_context, negotiation, &(id->pl.id),
                          return_p, return_len);
}

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshIkePacket"

/*                                                              shade{0.9}
 * Free SshIkePacket stuff. Note this will only release
 * the structure self, not the data pointed by those
 * structure (unless those pointers point to
 * SshIkePacket->packet_data_items or encoded_packet field
 * which are freed, the ike_decode_packet sets all data
 * to point that in buffer.                                     shade{1.0}
 */
void ike_free_packet(SshIkePacket isakmp_packet,
                     SshUInt32 compat_flags)
{
  int i, j, k, l;
  SshIkePayloadPProtocol prot;

  SSH_DEBUG(12, ("Start"));
  for (i = 0; i < isakmp_packet->number_of_payload_packets; i++)
    {
      SshIkePayload isakmp_payload = isakmp_packet->payloads[i];
      if (isakmp_payload == NULL)
        continue;
      switch (isakmp_payload->type)
        {
        case SSH_IKE_PAYLOAD_TYPE_SA:
          for (j = 0; j < isakmp_payload->pl.sa.number_of_proposals; j++)
            {
              for (k = 0;
                  k < isakmp_payload->pl.sa.proposals[j].number_of_protocols;
                  k++)
                {
                  prot = &isakmp_payload->pl.sa.proposals[j].protocols[k];
                  if (prot->transforms)
                    {
                      for (l = 0; l < prot->number_of_transforms; l++)
                        ssh_free(prot->transforms[l].sa_attributes);
                      ssh_free(prot->transforms);
                    }
                }
              ssh_free(isakmp_payload->pl.sa.proposals[j].protocols);
            }
          if (isakmp_payload->pl.sa.proposals != NULL)
            ssh_free(isakmp_payload->pl.sa.proposals);
          break;
        case SSH_IKE_PAYLOAD_TYPE_CR:
        case SSH_IKE_PAYLOAD_TYPE_KE:
        case SSH_IKE_PAYLOAD_TYPE_ID:
        case SSH_IKE_PAYLOAD_TYPE_CERT:
        case SSH_IKE_PAYLOAD_TYPE_HASH:
        case SSH_IKE_PAYLOAD_TYPE_SIG:
        case SSH_IKE_PAYLOAD_TYPE_NONCE:
        case SSH_IKE_PAYLOAD_TYPE_N:
        case SSH_IKE_PAYLOAD_TYPE_VID:
        case SSH_IKE_PAYLOAD_TYPE_PRV:
          /* Nothing to be freed */
          break;
        case SSH_IKE_PAYLOAD_TYPE_D:
          if (isakmp_payload->pl.d.spis != NULL)
            ssh_free(isakmp_payload->pl.d.spis);
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_PAYLOAD_TYPE_ATTR:
          ssh_free(isakmp_payload->pl.attr.attributes);
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        default:
          ssh_warning("Internal error in ike_free_packet, got invalid "
                      "packet type: %d", isakmp_payload->type);
          break;
        }
      ssh_free(isakmp_packet->payloads[i]);
    }
  ssh_free(isakmp_packet->payloads);
  if (isakmp_packet->packet_data_items != NULL)
    {
      for (i = 0; i < isakmp_packet->packet_data_items_cnt; i++)
        ssh_free(isakmp_packet->packet_data_items[i]);
      ssh_free(isakmp_packet->packet_data_items);
    }
  if (isakmp_packet->encoded_packet != NULL)
    ssh_free(isakmp_packet->encoded_packet);
  ssh_free(isakmp_packet);
  return;
}
