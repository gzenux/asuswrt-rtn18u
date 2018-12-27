/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Payload Decode routines.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshIkev2Decode"

/* Each of these functions will get the payload and the
   payload length. the payload will not have the generic
   header anymore, i.e it is only the raw data. */

/* Decode SA payload. */
SshIkev2Error ikev2_decode_sa(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  int proposal_number, last_proposal, number_of_transforms;
  SshIkev2ProtocolIdentifiers protocol;
  SshUInt32 transform_attribute;
  SshIkev2TransformType type;
  SshIkev2TransformID id;
  SshIkev2PayloadSA sa;
  SshIkev2Error err;
  size_t tlen, len;
  size_t spi_size;
  int trans;
  int prop;

  if (packet->ed->sa != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate SA payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  sa = ssh_ikev2_sa_allocate(ike_sa->server->sad_handle);
  if (sa == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  packet->ed->sa = sa;
  sa->proposal_number = 0;

  last_proposal = 0;
  prop = -1;
  while (payload_len > 0)
    {
      if (payload_len < 8)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 8",
                                          payload_len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      /* Get the proposal substructure len. */
      len = SSH_GET_16BIT(payload + 2);
      if (SSH_GET_8BIT(payload) == 0)
        {
          if (len != payload_len)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Payload_len(%d) != proposal_len(%d)",
                               payload_len, len));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

        }
      else if (SSH_GET_8BIT(payload) != 2)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Next payload(%d) not 0 or 2",
                                          SSH_GET_8BIT(payload)));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      proposal_number = SSH_GET_8BIT(payload + 4);
      protocol = SSH_GET_8BIT(payload + 5);
      spi_size = SSH_GET_8BIT(payload + 6);
      number_of_transforms = SSH_GET_8BIT(payload + 7);

      if (proposal_number == 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Proposal number(%d) == 0",
                                          proposal_number));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      if (len > payload_len)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < proposal_len(%d)",
                                          payload_len, len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      /* Skip proposal header. */
      payload += 8;
      payload_len -= 8;
      len -= 8;

      if (proposal_number == last_proposal)
        {
          /* We do not support Multiple protocols, we need
             to skip this whole proposal, thus set the
             protocol_id to 0 marking we skip this. Prop
             cannot be -1 as that would mean last_proposal was 0
             and proposal_number was 0, in which case we would have
             returned error earlier. */
          if (prop < SSH_IKEV2_SA_MAX_PROPOSALS)
            {
              sa->protocol_id[prop] = 0;
            }
          /* Note, that we MUST NOT increment the prop here, as we always
             assume that the proposal_index and proposal_number are tied to
             gether (i.e. proposal_number = proposal_index + 1). */
        }
      else if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
          /* This is responders reply, so there must be only
             one proposal, and it can have any number it
             likes. */
          if (sa->proposal_number != 0)
            {
              /* This is not only proposal, return error. */
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Multiple proposal in the reply"));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }
          sa->proposal_number = proposal_number;
          /* We use the first slot for the replies. */
          prop = 0;
          sa->protocol_id[prop] = protocol;
        }
      else if (proposal_number != last_proposal + 1)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Proposal number(%d) should be %d",
                                          proposal_number, prop + 1));
          /* Error, proposal numbers do not increment by one. */
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      else
        {
          /* New proposal. */
          prop++;

          if (prop < SSH_IKEV2_SA_MAX_PROPOSALS)
            {
              sa->protocol_id[prop] = protocol;
            }
        }
      last_proposal = proposal_number;

      if (payload_len < spi_size || len < spi_size)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Payload_len(%d) or proposal_len(%d) < "
                           "spi_size(%d)",
                           payload_len, len, spi_size));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      if (protocol == SSH_IKEV2_PROTOCOL_ID_IKE && spi_size == 8)
        {
          memcpy(sa->spis.ike_spi, payload, 8);
          sa->spi_len = 8;
        }
      else if (protocol == SSH_IKEV2_PROTOCOL_ID_IKE && spi_size == 0)
        {
          /* Initial IKE SA creation. */
          sa->spi_len = 0;
        }
      else if (spi_size == 4 &&
               (protocol == SSH_IKEV2_PROTOCOL_ID_AH ||
                protocol == SSH_IKEV2_PROTOCOL_ID_ESP))
        {
          if (prop < SSH_IKEV2_SA_MAX_PROPOSALS)
            {
              /* AH or ESP SA, spi size 4. */
              if (packet->ed->ipsec_ed == NULL)
                {
                  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                  ("AH or ESP while not negotiating "
                                   "IPsec SA"));
                  return SSH_IKEV2_ERROR_INVALID_SYNTAX;
                }
              sa->spis.ipsec_spis[prop] = SSH_GET_32BIT(payload);
              sa->spi_len = 4;
            }
        }
      else
        {
          /* Invalid protocol or spi_size. */
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Invalid protocol(%d) or spi size(%d)",
                           protocol, spi_size));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      /* Skip spi. */
      payload += spi_size;
      payload_len -= spi_size;
      len -= spi_size;

      for(trans = 0; trans < number_of_transforms; trans++)
        {
          if (payload_len < 8 || len < 8)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Payload_len(%d) or proposal_len(%d) < 8",
                               payload_len, len));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

          tlen = SSH_GET_16BIT(payload + 2);

          if (tlen < 8)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("transform_len(%d) < 8", tlen));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

          if (SSH_GET_8BIT(payload) == 0)
            {
              if (tlen != len)
                {
                  SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                                  ("Last transform, but transform_len(%d)"
                                   " != len(%d)",
                                   tlen, len));
                  return SSH_IKEV2_ERROR_INVALID_SYNTAX;
                }
            }
          else if (SSH_GET_8BIT(payload) != 3)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Next payload type not 0 or 3 (%d)",
                               SSH_GET_8BIT(payload)));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

          type = SSH_GET_8BIT(payload + 4);
          id = SSH_GET_16BIT(payload + 6);

          /* Skip transform header. */
          payload += 8;
          payload_len -= 8;
          len -= 8;
          tlen -= 8;

          if (payload_len < tlen || len < tlen)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Payload_len(%d) or proposal_len(%d) < "
                               "transform_len(%d)",
                               payload_len, len, tlen));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

          if (tlen == 0)
            {
              transform_attribute = 0;
            }
          else if (tlen == 4)
            {
              /* Only one attribute, and that must be 4 bytes. */
              transform_attribute = SSH_GET_32BIT(payload);
              /* Skip it. */
              payload += 4;
              payload_len -= 4;
              len -= 4;
            }
          else
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                              ("Transform attribute len not 0 or 4 (%d)",
                               tlen));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }

          if (prop < SSH_IKEV2_SA_MAX_PROPOSALS)
            {
              err = ssh_ikev2_sa_add(sa, (SshUInt8) prop, type,
                                     id, transform_attribute);
              if (err != SSH_IKEV2_ERROR_OK)
                return err;
            }
        }
      /* Check that there is no extra data. */
      if (len != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Extra data after proposal len != 0 (%d)", len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      /* Note, we only store SSH_IKEV2_SA_MAX_PROPOSALS
         proposals, but we do decode all of them, just in
         case there is errors, and if so, we detect them. */
    }
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_sa_render, sa);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode KE payload. */
SshIkev2Error ikev2_decode_ke(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len)
{
  size_t len;

  if (payload_len < 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (packet->ed->ke != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate KE payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  packet->ed->ke =
    ssh_obstack_alloc(packet->ed->obstack, sizeof(*packet->ed->ke));
  if (packet->ed->ke == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating KE"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  packet->ed->ke->dh_group = SSH_GET_16BIT(payload);

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  if (packet->ed->ke->dh_group >= SSH_IKEV2_TRANSFORM_D_H_MAX)
    {
      /* TODO: add support for private configured groups
         here. Fetch the size of the group in bits and put
         it in the len variable. If group number is invalid
         return the INVALID_KE_PAYLOAD error. */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Trying to use unsupported private group %d",
                       (int) packet->ed->ke->dh_group));
      return SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD;
    }
  else
    {
      len = ssh_ikev2_predefined_group_lengths[packet->ed->ke->dh_group];
    }

  /* Convert to bytes. */
  len = (len + 7) / 8;

  /* Check that the KE payload has right size. */
  if (payload_len != len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload length(%d) != group_length(%d)",
                                      payload_len, len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  packet->ed->ke->key_exchange_len = len;
  packet->ed->ke->key_exchange_data =
    ssh_obstack_alloc_unaligned(packet->ed->obstack, len);
  if (packet->ed->ke->key_exchange_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating key_exchange_data"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  memcpy(packet->ed->ke->key_exchange_data, payload, len);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@",
                         ssh_ikev2_payload_ke_render, packet->ed->ke);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode ID payload. */
SshIkev2Error ikev2_decode_id(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len,
                              SshIkev2PayloadID *id_return,
                              int id_type)
{
  size_t len;

  /* There must be at least one byte of the id data too. */
  if (payload_len <= 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) <= 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (*id_return != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate ID payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  *id_return = ssh_obstack_alloc(packet->ed->obstack,
                                 sizeof(**id_return));
  if (*id_return == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating ID"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  (*id_return)->id_type = SSH_GET_8BIT(payload);
  (*id_return)->id_reserved = SSH_GET_32BIT(payload) & 0xffffff;

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  switch ((*id_return)->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR: len = 4; break;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR: len = 16; break;
    case SSH_IKEV2_ID_TYPE_FQDN:
    case SSH_IKEV2_ID_TYPE_RFC822_ADDR:
    case SSH_IKEV2_ID_TYPE_ASN1_DN:
    case SSH_IKEV2_ID_TYPE_ASN1_GN:
    case SSH_IKEV2_ID_TYPE_KEY_ID:
      len = 0;  break;
    default:
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Invalid ID type: %d",
                                (*id_return)->id_type));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  if (len != 0 && payload_len != len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) != len(%d)",
                                      payload_len, len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  (*id_return)->id_data_size = payload_len;
  (*id_return)->id_data = ssh_obstack_memdup(packet->ed->obstack,
                                             payload, payload_len);
  if ((*id_return)->id_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating id_data"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  SSH_IKEV2_DEBUG_DECODE(packet, "%.*@",
                         id_type, ssh_ikev2_payload_id_render, *id_return);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode IDi payload. */
SshIkev2Error ikev2_decode_idi(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len)
{
  if (packet->ed->ike_ed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("IDi payload in wrong exchange"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (packet->ed->ike_ed->id_i)
    {
      SSH_IKEV2_DEBUG(SSH_D_MIDOK,
                      ("Received second initiator identity payload "
                       "in the negotiation."));
      return ikev2_decode_id(packet, payload, payload_len,
                             &(packet->ed->ike_ed->second_id_i), 1);

    }
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    return ikev2_decode_id(packet, payload, payload_len,
                           &(packet->ed->ike_ed->id_i), 1);
}

/* Decode IDr payload. */
SshIkev2Error ikev2_decode_idr(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len)
{
  if (packet->ed->ike_ed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("IDr payload in wrong exchange"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  return ikev2_decode_id(packet, payload, payload_len,
                         &(packet->ed->ike_ed->id_r), 2);
}

/* Decode Cert payload. */
SshIkev2Error ikev2_decode_cert(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshIkev2CertEncoding cert_encoding;
  SshIkev2Sa ike_sa = packet->ike_sa;

  /* There must be at least 1 byte of certificate too. */
  if (payload_len <= 1)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) <= 1", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  cert_encoding = SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload++;
  payload_len--;

  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, new_certificate)
    (ike_sa->server->sad_handle, packet->ed,
     cert_encoding, payload, payload_len);

  if (packet->ed->ike_ed != NULL && packet->ed->ike_ed->ee_cert == NULL)
    {
      packet->ed->ike_ed->ee_cert =
        ssh_obstack_alloc(packet->ed->obstack,
                          sizeof(*packet->ed->ike_ed->ee_cert));
      if (packet->ed->ike_ed->ee_cert == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating ee_cert"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
      packet->ed->ike_ed->ee_cert->cert_encoding = cert_encoding;
      packet->ed->ike_ed->ee_cert->cert_size = payload_len;
      packet->ed->ike_ed->ee_cert->cert_data =
        ssh_obstack_memdup(packet->ed->obstack,
                           payload, payload_len);
      if (packet->ed->ike_ed->ee_cert->cert_data == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating cert_data"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
      SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_cert_render,
                             packet->ed->ike_ed->ee_cert);
    }
  else
    {
      SSH_IKEV2_DEBUG_DECODE_HEX(
                       packet, payload_len, payload,
                       "CERT(encoding = %s (%d), len = %d, data =",
                       ssh_ikev2_cert_encoding_to_string(cert_encoding),
                       cert_encoding, payload_len);
    }
#endif /* SSHDIST_IKE_CERT_AUTH */
  return SSH_IKEV2_ERROR_OK;
}

/* Decode certificate request payload. */
SshIkev2Error ikev2_decode_certreq(SshIkev2Packet packet,
                                   const unsigned char *payload,
                                   size_t payload_len)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshIkev2CertEncoding cert_encoding;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (payload_len < 1)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 1", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  cert_encoding = SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload++;
  payload_len--;

  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, new_certificate_request)
    (ike_sa->server->sad_handle, packet->ed,
     cert_encoding, payload, payload_len);
  SSH_IKEV2_DEBUG_DECODE_HEX(packet, payload_len, payload,
                  "CERTREQ(encoding = %s (%d), len = %d, data =",
                   ssh_ikev2_cert_encoding_to_string(cert_encoding),
                   cert_encoding, payload_len);
#endif /* SSHDIST_IKE_CERT_AUTH */
  return SSH_IKEV2_ERROR_OK;
}

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* Decode secondary AUTH payload. */
SshIkev2Error ikev2_decode_secondary_auth(SshIkev2Packet packet,
                                          const unsigned char *payload,
                                          size_t payload_len)
{
  /* TODO: check that in right state of multiple auth */

  packet->ed->ike_ed->second_auth_remote =
    ssh_obstack_alloc(packet->ed->obstack,
                      sizeof(*packet->ed->ike_ed->second_auth_remote));

  if (packet->ed->ike_ed->second_auth_remote == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating auth_remote"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  packet->ed->ike_ed->second_auth_remote->auth_method =
    SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  packet->ed->ike_ed->second_auth_remote->authentication_size = payload_len;
  packet->ed->ike_ed->second_auth_remote->authentication_data =
    ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
  if (packet->ed->ike_ed->second_auth_remote->authentication_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating secondary "
                       "authentication_data"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  memcpy(packet->ed->ike_ed->second_auth_remote->authentication_data,
         payload, payload_len);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_auth_render,
                         packet->ed->ike_ed->second_auth_remote);

  return SSH_IKEV2_ERROR_OK;
}

#endif /* SSH_IKEV2_MULTIPLE_AUTH */


/* Decode AUTH payload. */
SshIkev2Error ikev2_decode_auth(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len)
{
  if (packet->ed->ike_ed == NULL)
    return SSH_IKEV2_ERROR_INVALID_SYNTAX;

  if (payload_len < 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 1", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (packet->ed->ike_ed->auth_remote != NULL)
    {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Second AUTH payload from peer"));
      return ikev2_decode_secondary_auth(packet, payload, payload_len);
#else /* SSH_IKEV2_MULTIPLE_AUTH */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate AUTH payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    }


  packet->ed->ike_ed->auth_remote =
    ssh_obstack_alloc(packet->ed->obstack,
                      sizeof(*packet->ed->ike_ed->auth_remote));
  if (packet->ed->ike_ed->auth_remote == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating auth_remote"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  packet->ed->ike_ed->auth_remote->auth_method = SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  packet->ed->ike_ed->auth_remote->authentication_size = payload_len;
  packet->ed->ike_ed->auth_remote->authentication_data =
    ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
  if (packet->ed->ike_ed->auth_remote->authentication_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating authentication_data"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  memcpy(packet->ed->ike_ed->auth_remote->authentication_data,
         payload, payload_len);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_auth_render,
                         packet->ed->ike_ed->auth_remote);

  return SSH_IKEV2_ERROR_OK;
}

/* Decode NONCE payload. */
SshIkev2Error ikev2_decode_nonce(SshIkev2Packet packet,
                                 const unsigned char *payload,
                                 size_t payload_len)
{
  if (payload_len < 16 || payload_len > 256)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 16 or > 256",
                                      payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (packet->ed->nonce != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate NONCE payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  packet->ed->nonce = ssh_obstack_alloc(packet->ed->obstack,
                                        sizeof(*packet->ed->nonce));
  if (packet->ed->nonce == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating NONCE"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  packet->ed->nonce->nonce_size = payload_len;
  packet->ed->nonce->nonce_data =
    ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
  if (packet->ed->nonce->nonce_data == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating nonce_data"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  memcpy(packet->ed->nonce->nonce_data, payload, payload_len);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_nonce_render,
                         packet->ed->nonce);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode notify payload. */
SshIkev2Error ikev2_decode_notify(SshIkev2Packet packet,
                                  Boolean authenticated,
                                  const unsigned char *payload,
                                  size_t payload_len)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadNotify notify;
  unsigned char *data;
  SshIkev2NotifyState notify_state;

  if (payload_len < 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  notify = ssh_obstack_alloc(packet->ed->obstack, sizeof(*notify));
  if (notify == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating notify"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  notify->next_notify = packet->ed->notify;
  packet->ed->notify = notify;

  notify->authenticated = authenticated;
  notify->protocol = SSH_GET_8BIT(payload);
  notify->spi_size = SSH_GET_8BIT(payload + 1);
  notify->notify_message_type = SSH_GET_16BIT(payload + 2);
  notify->spi_data = NULL;
  notify->notification_data = NULL;
  notify->notification_size = 0;

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  if (notify->spi_size > payload_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < spi_size(%d)",
                                      payload_len, notify->spi_size));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (payload_len > 0)
    {
      data = ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
      if (data == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating data"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }

      memcpy(data, payload, payload_len);

      if (notify->spi_size > 0)
        {
          notify->spi_data = data;
          data += notify->spi_size;
          /* payload += notify->spi_size; */
          payload_len -= notify->spi_size;
        }
      if (payload_len > 0)
        {
          notify->notification_data = data;
          notify->notification_size = payload_len;
        }
    }

  notify_state = authenticated ? SSH_IKEV2_NOTIFY_STATE_AUTHENTICATED_INITIAL :
    SSH_IKEV2_NOTIFY_STATE_UNAUTHENTICATED_INITIAL;

  /* Store unprotected error notify codes to
     ike_sa->received_unprotected_error. */
  if (!authenticated
      && ike_sa->received_unprotected_error == SSH_IKEV2_ERROR_OK
      && notify->notify_message_type != 0
      && notify->notify_message_type < 0x4000)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Storing information about received unprotected error notify "
                 "'%s' (%d) to IKE SA %p",
                 ssh_ikev2_error_to_string((int) notify->notify_message_type),
                 (int) notify->notify_message_type,
                 ike_sa));
      ike_sa->received_unprotected_error = (int) notify->notify_message_type;

      /* Adjust retransmit counters for ongoing exchanges of the IKE SA. */
      ikev2_window_set_retransmit_count
        (ike_sa, packet->server->context->params.retry_limit + 1
         - SSH_IKEV2_PACKET_UNPROTECTED_ERROR_RETRANSMIT_COUNT);
    }

  packet->ed->notify_count++;
  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, notify_received)
    (ike_sa->server->sad_handle, notify_state, packet->ed,
     notify->protocol, notify->spi_data, notify->spi_size,
     notify->notify_message_type,
     notify->notification_data,
     notify->notification_size);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@",
                         ssh_ikev2_payload_notify_render, notify);

  return SSH_IKEV2_ERROR_OK;
}

/* Decode delete payload. */
SshIkev2Error ikev2_decode_delete(SshIkev2Packet packet,
                                  const unsigned char *payload,
                                  size_t payload_len)
{
  SshIkev2PayloadDelete delete_payload;

  if (payload_len < 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  delete_payload = ssh_obstack_alloc(packet->ed->obstack,
                                     sizeof(*delete_payload));
  if (delete_payload == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating delete"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  delete_payload->next_delete = packet->ed->delete_payloads;
  packet->ed->delete_payloads = delete_payload;

  delete_payload->protocol = SSH_GET_8BIT(payload);
  delete_payload->spi_size = SSH_GET_8BIT(payload + 1);
  delete_payload->number_of_spis = SSH_GET_16BIT(payload + 2);
  delete_payload->spi.spi_table = NULL;

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  if (delete_payload->spi_size * delete_payload->number_of_spis != payload_len)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Payload_len(%d) != spi_size(%d) * num_spis(%d)",
                       payload_len, delete_payload->spi_size,
                       delete_payload->number_of_spis));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (payload_len > 0)
    {
      if (delete_payload->spi_size == 4)
        {
          int i;

          delete_payload->spi.spi_array =
            ssh_obstack_alloc(packet->ed->obstack,
                              delete_payload->number_of_spis *
                              sizeof(SshUInt32));
          if (delete_payload->spi.spi_array == NULL)
            {
              SSH_IKEV2_DEBUG(SSH_D_ERROR,
                              ("Error: Out of memory allocating spis"));
              return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }

          SSH_ASSERT(delete_payload->number_of_spis <
                     (SSH_IKEV2_MAX_PAYLOAD_SIZE / 4));

          for (i = 0; i < delete_payload->number_of_spis; i++)
            {
              delete_payload->spi.spi_array[i] =
                SSH_GET_32BIT(payload + i * 4);
            }
        }
      else
        {
          delete_payload->spi.spi_table =
            ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
          if (delete_payload->spi.spi_table == NULL)
            {
              SSH_IKEV2_DEBUG(SSH_D_ERROR,
                              ("Error: Out of memory allocating spis"));
              return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
            }
          memcpy(delete_payload->spi.spi_table, payload, payload_len);
        }
    }
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_delete_render,
                         delete_payload);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode vendor ID payload. */
SshIkev2Error ikev2_decode_vendor_id(SshIkev2Packet packet,
                                     const unsigned char *payload,
                                     size_t payload_len)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadVendorID vid;

  vid = ssh_obstack_alloc(packet->ed->obstack, sizeof(*vid));
  if (vid == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating VID"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  vid->next_vid = packet->ed->vid;
  packet->ed->vid = vid;

  vid->vendorid_size = payload_len;
  vid->vendorid_data = NULL;

  if (payload_len > 0)
    {
      vid->vendorid_data =
        ssh_obstack_alloc_unaligned(packet->ed->obstack, payload_len);
      if (vid->vendorid_data == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating vid_data"));
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
      memcpy(vid->vendorid_data, payload, payload_len);
    }

  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, vendor_id)
    (ike_sa->server->sad_handle, packet->ed,
     vid->vendorid_data, vid->vendorid_size);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_vid_render, vid);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode TS payload. */
SshIkev2Error ikev2_decode_ts(SshIkev2Packet packet,
                              const unsigned char *payload,
                              size_t payload_len,
                              SshIkev2PayloadTS *ts_return,
                              int ts_type)
{
  SshInetIPProtocolID proto;
  SshIpAddrStruct start_address[1];
  SshIpAddrStruct end_address[1];
  SshUInt16 start_port;
  SshUInt16 end_port;
  SshIkev2TSType type;
  SshIkev2Error err;
  int number_of_ts;
  size_t len;
  int i;

  /* There must be at least one byte of the traffic selector data too. */
  if (payload_len <= 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) <= 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  if (*ts_return != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate TS payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  *ts_return = ssh_ikev2_ts_allocate(packet->ike_sa->server->sad_handle);
  if (*ts_return == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: Out of memory allocating TS"));
      return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
    }

  number_of_ts = SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  for(i = 0; i < number_of_ts; i++)
    {
      if (payload_len <= 8)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) <= 8",
                                          payload_len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      type = SSH_GET_8BIT(payload);
      proto = SSH_GET_8BIT(payload + 1);
      len = SSH_GET_16BIT(payload + 2);
      start_port = SSH_GET_16BIT(payload + 4);
      end_port = SSH_GET_16BIT(payload + 6);

      if (len <= 8 || len > payload_len)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("ts_len(%d) <= 8 || Payload_len(%d) <= ts_len(%d)",
                           len, payload_len, len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      /* Skip item header. */
      payload += 8;
      payload_len -= 8;
      len -= 8;

      switch (type)
        {
        case SSH_IKEV2_TS_IPV4_ADDR_RANGE:
          if (len != 8)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("IPv4 range len(%d) != 8", len));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }
          break;
        case SSH_IKEV2_TS_IPV6_ADDR_RANGE:
          if (len != 32)
            {
              SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("IPv4 range len(%d) != 32",
                                              len));
              return SSH_IKEV2_ERROR_INVALID_SYNTAX;
            }
          break;
        default:
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Unsupported type = %d", type));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }
      SSH_IP_DECODE(start_address, payload, len / 2);
      SSH_IP_DECODE(end_address, payload + len / 2, len / 2);

      /* Skip the data. */
      payload += len;
      payload_len -= len;

      /* Add the item. */
      err = ssh_ikev2_ts_item_add(*ts_return, proto,
                                  start_address, end_address,
                                  start_port, end_port);
      if (err != SSH_IKEV2_ERROR_OK)
        return err;
    }
  if (payload_len != 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) != 0", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  SSH_IKEV2_DEBUG_DECODE(packet, "%.*@",
                         ts_type, ssh_ikev2_payload_ts_render, *ts_return);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode TSi payload. */
SshIkev2Error ikev2_decode_tsi(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len)
{
  if (packet->ed->ipsec_ed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("TSi payload in wrong exchange"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  return ikev2_decode_ts(packet, payload, payload_len,
                         &(packet->ed->ipsec_ed->ts_i), 1);
}

/* Decode TSr payload. */
SshIkev2Error ikev2_decode_tsr(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len)
{
  if (packet->ed->ipsec_ed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("TSr payload in wrong exchange"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }
  return ikev2_decode_ts(packet, payload, payload_len,
                         &(packet->ed->ipsec_ed->ts_r), 2);
}

/* Decode configuration payload. */
SshIkev2Error ikev2_decode_conf(SshIkev2Packet packet,
                                const unsigned char *payload,
                                size_t payload_len)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadConf conf;
  SshIkev2ConfType conf_type;
  SshIkev2Error err;
  SshUInt16 attr_type;
  size_t len;

  if (payload_len < 4)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 4", payload_len));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  conf_type = SSH_GET_8BIT(payload);

  /* Skip the header. */
  payload += 4;
  payload_len -= 4;

  if (packet->ed->conf != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Duplicate CONF payload"));
      return SSH_IKEV2_ERROR_INVALID_SYNTAX;
    }

  conf = ssh_ikev2_conf_allocate(ike_sa->server->sad_handle,
                                 conf_type);
  if (conf == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  packet->ed->conf = conf;

  while (payload_len > 0)
    {
      if (payload_len < 4)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Payload_len(%d) < 4",
                                          payload_len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      attr_type = SSH_GET_16BIT(payload) & 0x7fff;
      len = SSH_GET_16BIT(payload + 2);

      /* Skip attribute header. */
      payload += 4;
      payload_len -= 4;

      if (len > payload_len)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Payload_len(%d) < attribute_len(%d)",
                           payload_len, len));
          return SSH_IKEV2_ERROR_INVALID_SYNTAX;
        }

      err = ssh_ikev2_conf_add(conf, attr_type, len, payload);
      if (err != SSH_IKEV2_ERROR_OK)
        return err;

      /* Skip the data. */
      payload += len;
      payload_len -= len;
    }
  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, conf_received)
    (ike_sa->server->sad_handle, packet->ed, conf);
  SSH_IKEV2_DEBUG_DECODE(packet, "%@", ssh_ikev2_payload_conf_render, conf);
  return SSH_IKEV2_ERROR_OK;
}

/* Decode EAP payload. */
SshIkev2Error ikev2_decode_eap(SshIkev2Packet packet,
                               const unsigned char *payload,
                               size_t payload_len)
{
#ifdef SSHDIST_IKE_EAP_AUTH
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_DEBUG_DECODE_HEX(packet, payload_len, payload,
                             "EAP(len = %d, data =", payload_len);
  /* OK, added to the ike_state_decode. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, eap_received)
    (ike_sa->server->sad_handle, packet->ed, payload, payload_len);
#endif /* SSHDIST_IKE_EAP_AUTH */
  return SSH_IKEV2_ERROR_OK;
}
