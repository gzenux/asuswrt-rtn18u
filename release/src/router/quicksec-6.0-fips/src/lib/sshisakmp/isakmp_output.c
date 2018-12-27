/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp state machine output functions module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#ifdef SSHDIST_CERT
#include "sshpkcs7.h"
#endif /* SSHDIST_CERT */

#define SSH_DEBUG_MODULE "SshIkeOutput"

/* Register spis values. */
SshIkeNotifyMessageType ike_st_o_sa_spi_register(SshIkeContext
                                                 isakmp_context,
                                                 SshIkePacket
                                                 isakmp_output_packet,
                                                 SshIkePayloadSA sa)
{
  SshIkePayloadPProtocol proto;
  int proposal, protocol;

  for (proposal = 0; proposal < sa->number_of_proposals; proposal++)
    {
      for (protocol = 0;
          protocol < sa->proposals[proposal].number_of_protocols;
          protocol++)
        {
          proto = &(sa->proposals[proposal].protocols[protocol]);

          if (proto->spi != NULL)
            {
              /* Register spi, because it has been allocated by the caller by
                 separate malloc */
              if (!ike_register_item(isakmp_output_packet, proto->spi))
                {
                  /* Error, free all spis, we ware not able to register. */
                  for (;
                       protocol < sa->proposals[proposal].number_of_protocols;
                       protocol++)
                    {
                      proto = &(sa->proposals[proposal].protocols[protocol]);
                      ssh_free(proto->spi);
                    }
                  for (; proposal < sa->number_of_proposals; proposal++)
                    {
                      for (protocol = 0;
                          protocol < sa->proposals[proposal].
                            number_of_protocols;
                          protocol++)
                        {
                          proto = &(sa->proposals[proposal].
                                    protocols[protocol]);
                          ssh_free(proto->spi);
                        }
                    }
                  return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
                }
            }
        }
    }
  return 0;
}

/* Allocate spi */
SshIkeNotifyMessageType ike_st_o_sa_spi_alloc(SshIkeContext isakmp_context,
                                              SshIkePacket
                                              isakmp_output_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              unsigned char **spi,
                                              size_t *spi_size)
{
  if (negotiation->ed->compat_flags & SSH_IKE_FLAGS_USE_ZERO_SPI)
    {
      *spi_size = isakmp_context->spi_size;
      *spi = ike_register_new(isakmp_output_packet, *spi_size);
      if (*spi == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  else
    {
      *spi_size = SSH_IKE_COOKIE_LENGTH;
      *spi = ike_register_copy(isakmp_output_packet,
                               isakmp_sa->cookies.initiator_cookie,
                               SSH_IKE_COOKIE_LENGTH);
      if (*spi == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_sa_proposal
 * Create output sa proposal (initiator). The sa comes
 * from ssh_ike_connect.                                        shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_sa_proposal(SshIkeContext isakmp_context,
                                             SshIkePacket isakmp_input_packet,
                                             SshIkePacket isakmp_output_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  int proposal, protocol;
  SshIkePayloadSA sa;
  unsigned char *spi;
  size_t spi_size;

  SSH_DEBUG(5, ("Start"));

  /* Append payload */
  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_SA);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Replace SA payload it with our own SA payload. */
  memmove(&(pl->pl.sa), negotiation->ike_ed->local_sa_proposal,
          sizeof(struct SshIkePayloadSARec));

  /* Free local_sa_proposal and mark it empty (note the data allocated
     in the next level of sa proposal is still in use by pl.sa, and is not
     freed, until the exchange_data is freed. */
  ssh_free(negotiation->ike_ed->local_sa_proposal);
  negotiation->ike_ed->local_sa_proposal = NULL;

  /* Store exchange_data */
  negotiation->ike_ed->sa_i = pl;

  ret = ike_st_o_sa_spi_alloc(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation, &spi, &spi_size);
  if (ret != 0)
    return ret;

  sa = &(pl->pl.sa);

  /* First make sure the spi are registered. */
  ret = ike_st_o_sa_spi_register(isakmp_context, isakmp_output_packet, sa);
  if (ret != 0)
    return ret;

  for (proposal = 0; proposal < sa->number_of_proposals; proposal++)
    {
      for (protocol = 0;
          protocol < sa->proposals[proposal].number_of_protocols;
          protocol++)
        {
          SshIkePayloadPProtocol proto;
          proto = &(sa->proposals[proposal].protocols[protocol]);

          /* Check protocol id */
          if (proto->protocol_id != SSH_IKE_PROTOCOL_ISAKMP)
            continue;

          if (proto->spi == NULL)
            {
              proto->spi = spi;
              proto->spi_size = spi_size;
            }
        }
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_sa_values
 * Create sa payload with our response values for
 * other ends proposal (responder).                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_sa_values(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  SshIkePayloadSA sa, sa_p;
  SshIkePayloadPProtocol proto, proto_p;
  SshIkePayloadT t, t_p;
  int i;

  int sel_prop, sel_trans;

  SSH_DEBUG(5, ("Start"));

  /* Find initiatior proposal */
  sa_p = &(negotiation->ike_ed->sa_i->pl.sa);
  sel_prop = negotiation->ike_ed->selected_proposal;
  sel_trans = negotiation->ike_ed->selected_transform;

  if (sel_prop < 0 || sel_trans < 0)
    {
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }

  if (negotiation->ike_ed->group == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_SA);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  sa = &(pl->pl.sa);
  sa->doi = SSH_IKE_DOI_IPSEC;
  sa->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;

  sa->number_of_proposals = 1;
  sa->proposals = ssh_calloc(1, sizeof(struct SshIkePayloadPRec));
  if (sa->proposals == NULL)
    {
      sa->number_of_proposals = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  sa->proposals[0].proposal_number =
    sa_p->proposals[sel_prop].proposal_number;
  sa->proposals[0].number_of_protocols = 1;
  sa->proposals[0].protocols =
    ssh_calloc(1, sizeof(struct SshIkePayloadPProtocolRec));
  if (sa->proposals[0].protocols == NULL)
    {
      sa->proposals[0].number_of_protocols = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Only one protocol */
  proto = &(sa->proposals[0].protocols[0]);
  proto_p = &(sa_p->proposals[sel_prop].protocols[0]);
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
  ret = ike_st_o_sa_spi_alloc(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              &proto->spi,
                              &proto->spi_size);
  if (ret != 0)
    return ret;

  proto->number_of_transforms = 1;
  proto->transforms = ssh_calloc(1, sizeof(struct SshIkePayloadTRec));
  if (proto->transforms == NULL)
    {
      proto->number_of_transforms = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  t = &(proto->transforms[0]);
  t_p = &(proto_p->transforms[sel_trans]);
  t->transform_number = t_p->transform_number;
  t->transform_id.generic = t_p->transform_id.generic;
  t->number_of_sa_attributes = t_p->number_of_sa_attributes;
  t->sa_attributes = ssh_calloc(t->number_of_sa_attributes,
                                sizeof(struct SshIkeDataAttributeRec));
  if (t->sa_attributes == NULL)
    {
      t->number_of_sa_attributes = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  for (i = 0; i < t->number_of_sa_attributes; i++)
    {
      /* Copy the pointers. This means we use the same storage than original sa
         proposal */
      t->sa_attributes[i] = t_p->sa_attributes[i];
    }

  /* Store exchange_data */
  negotiation->ike_ed->sa_r = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_ke_dh_setup_cb
 * Append Diffie-Hellman setup payload after async operation
 * is finished (ke).                                            shade{1.0}
 */

void ike_st_o_ke_dh_setup_cb(SshCryptoStatus status,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange_buffer,
                             size_t exchange_buffer_len,
                             void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->async_return_data =
        ssh_memdup(exchange_buffer, exchange_buffer_len);
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 1;
        }
      negotiation->ike_ed->async_return_data_len = exchange_buffer_len;
      negotiation->ike_ed->secret = secret;
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_pk_group_dh_setup_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}


/*                                                              shade{0.9}
 * ike_st_o_ke
 * Append Diffie-Hellman setup payload (ke).                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_ke(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkePacket isakmp_output_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
  SshIkePayload pl;
  size_t len;
  SshIkeNotifyMessageType ret;
  unsigned char *p;
  SshIkePayloadSA sa;
  SshOperationHandle handle;

  SSH_DEBUG(5, ("Start"));

  sa = negotiation->ike_ed->local_sa_proposal;
  if (sa == NULL && negotiation->ike_ed->sa_i != NULL)
    sa = &(negotiation->ike_ed->sa_i->pl.sa);
  if (sa == NULL)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("No sa payload found, could not find group information"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  ret = ike_find_group_from_sa(isakmp_context, isakmp_sa, negotiation, sa);
  if (ret)
    return ret;

  /* Find out how much data is needed */
  len = ssh_pk_group_dh_setup_max_output_length(negotiation->
                                                ike_ed->group->group);
  if (len == 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No Diffie-Hellman defined for group"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  if (negotiation->ike_ed->async_return_data_len == 0)
    {
      handle =
        ssh_pk_group_dh_setup_async(negotiation->ike_ed->group->group,
                                    ike_st_o_ke_dh_setup_cb,
                                    negotiation);
      /* Check if we started async operation, or if it is answered directly. */
      if (handle != NULL)
        {
          /* We started real async operation, go on wait */
          SSH_IKE_DEBUG(6, negotiation,
                        ("Asyncronous Diffie-Hellman "
                         "setup operation started"));
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }
  if (negotiation->ike_ed->async_return_data == NULL)
    {
      /* Error occurred during operation, return error */
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  p = negotiation->ike_ed->async_return_data;
  len = negotiation->ike_ed->async_return_data_len;
  negotiation->ike_ed->async_return_data = NULL;
  negotiation->ike_ed->async_return_data_len = 0;

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_KE);
  if (pl == NULL)
    {
      ssh_free(p);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Register allocated data */
  if (!ike_register_item(isakmp_output_packet, p))
    {
      ssh_free(p);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Store the information to ke-payload */
  pl->pl.ke.key_exchange_data_len = len;
  pl->pl.ke.key_exchange_data = p;

  /* Store exchange_data */
  if (negotiation->ike_pm_info->this_end_is_initiator)
    negotiation->ike_ed->ke_i = pl;
  else
    negotiation->ike_ed->ke_r = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_nonce
 * Append nonce payload.                                        shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_nonce(SshIkeContext isakmp_context,
                                       SshIkePacket isakmp_input_packet,
                                       SshIkePacket isakmp_output_packet,
                                       SshIkeSA isakmp_sa,
                                       SshIkeNegotiation negotiation,
                                       SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->ike_ed->nonce_data_len == -1)
    {
      /* Ask how much nonce data to add from policy manager */
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_isakmp_nonce_data_len(negotiation->ike_pm_info,
                                       ike_policy_reply_isakmp_nonce_data_len,
                                       negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  if (isakmp_output_packet->first_nonce_payload)
    {
      pl = isakmp_output_packet->first_nonce_payload;
    }
  else
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_NONCE);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Allocate nonce buffer */
      pl->pl.nonce.nonce_data_len = negotiation->ike_ed->nonce_data_len;
      pl->pl.nonce.nonce_data = ike_register_new(isakmp_output_packet,
                                                 pl->pl.nonce.nonce_data_len);
      if (pl->pl.nonce.nonce_data == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Generate random data */
      for (i = 0; i < pl->pl.nonce.nonce_data_len; i++)
        {
          pl->pl.nonce.nonce_data[i] =
            ssh_random_get_byte();
        }

      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Nonce data",
                           pl->pl.nonce.nonce_data_len,
                           pl->pl.nonce.nonce_data);
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  if (negotiation->ed->auth_method_type ==
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION)
    {
      /* If using rsa encryption authentication method encrypt the packet
         first. */
      SshIkeNotifyMessageType ret;
      unsigned char *p;
      size_t len;

      ret = ike_rsa_encrypt_data(isakmp_context, isakmp_sa, negotiation,
                                 pl->pl.nonce.nonce_data,
                                 pl->pl.nonce.nonce_data_len,
                                 &p, &len);
      if (ret != 0)
        return ret;

      /* Register the mallocated item */
      if (!ike_register_item(isakmp_output_packet, p))
        {
          ssh_free(p);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Encrypted nonce", len, p);
      pl->pl.nonce.raw_nonce_packet = p;
      pl->payload_length = len;
    }
  else
#endif /* SSHDIST_IKE_CERT_AUTH */
    {
      pl->pl.nonce.raw_nonce_packet = pl->pl.nonce.nonce_data;
      pl->payload_length = pl->pl.nonce.nonce_data_len;
    }

  /* Store exchange_data */
  if (negotiation->ike_pm_info->this_end_is_initiator)
    negotiation->ike_ed->nonce_i = pl;
  else
    negotiation->ike_ed->nonce_r = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_id
 * Handle id payload. Pack the payload to raw format and
 * encrypt it if using rsa encryption authentication mode.      shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_id(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkePacket isakmp_output_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  size_t len;
  SshIkePayload id;
  unsigned char *p;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->ike_pm_info->local_id == NULL)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_isakmp_id(negotiation->ike_pm_info,
                           ike_policy_reply_isakmp_id,
                           negotiation);
      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  if (negotiation->ike_pm_info->local_id == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;

  if (isakmp_output_packet->first_id_payload)
    {
      id = isakmp_output_packet->first_id_payload;
    }
  else
    {
      /* Append payload */
      id = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_ID);
      if (id == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      ret = ike_copy_id(isakmp_context, isakmp_output_packet, isakmp_sa,
                        negotiation, negotiation->ike_pm_info->local_id,
                        &(id->pl.id));
      if (ret != 0)
        return ret;
    }
  ret = ike_encode_id(isakmp_context, negotiation, id, &p, &len);
  if (ret != 0)
    return ret;

#ifdef SSHDIST_IKE_CERT_AUTH
  if (negotiation->ed->auth_method_type ==
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION)
    {
      SshIkeNotifyMessageType ret;

      /* Register the data to be encrypted. */
      if (!ike_register_item(isakmp_output_packet, p))
        {
          ssh_free(p);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }
      /* If using rsa encryption authentication method encrypt the packet
         first, this cannot return retry because of missing key, because we
         already make sure earlier that we have the encryption key ready. */
      ret = ike_rsa_encrypt_data(isakmp_context, isakmp_sa, negotiation,
                                 p, len, &id->pl.id.raw_id_packet, &len);
      if (ret != 0)
        return ret;

      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Encrypted id", len,
                           id->pl.id.raw_id_packet);
    }
  else
#endif /* SSHDIST_IKE_CERT_AUTH */
    {
      id->pl.id.raw_id_packet = p;
    }
  /* Register the mallocated data */
  if (!ike_register_item(isakmp_output_packet, id->pl.id.raw_id_packet))
    {
      ssh_free(id->pl.id.raw_id_packet);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Set payload length */
  id->payload_length = len;
  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_st_o_sig_sign_cb
 * Callback which is called when the async sign returns.        shade{1.0}
 */
void ike_st_o_sig_sign_cb(SshCryptoStatus status,
                          const unsigned char *signature_buffer,
                          size_t signature_buffer_len,
                          void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->async_return_data =
        ssh_memdup(signature_buffer, signature_buffer_len);
      if (negotiation->ike_ed->async_return_data == NULL)
        {
          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 1;
        }
      negotiation->ike_ed->async_return_data_len = signature_buffer_len;
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_private_key_sign_digest_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_st_o_sig
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_sig(SshIkeContext isakmp_context,
                                     SshIkePacket isakmp_input_packet,
                                     SshIkePacket isakmp_output_packet,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshCryptoStatus cret;
  SshIkePayload pl;
  unsigned char *hash;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  const unsigned char *mac_name;
  char *key_type;
  SshOperationHandle handle;

  SSH_DEBUG(5, ("Start"));

#ifdef SSHDIST_IKE_XAUTH
      if (negotiation->ike_pm_info->hybrid_client)
        {
          /* Add N payload containing hash of PSK */

          pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                                  isakmp_sa, negotiation,
                                  SSH_IKE_PAYLOAD_TYPE_N);
          if (pl == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

          hash = ike_register_new(isakmp_output_packet, hash_len);
          if (hash == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

          ret = ike_calc_psk_hash(isakmp_context, isakmp_sa, negotiation,
                                  hash, &hash_len);
          if (ret != 0)
            return ret;

          pl->pl.n.doi = SSH_IKE_DOI_IPSEC;
          pl->pl.n.protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
          pl->pl.n.notify_message_type = SSH_IKE_NOTIFY_MESSAGE_CISCO_PSK_HASH;
          if (!(negotiation->ed->compat_flags & SSH_IKE_FLAGS_USE_ZERO_SPI))
            {
              pl->pl.n.spi_size = 2 * SSH_IKE_COOKIE_LENGTH;
              pl->pl.n.spi = ike_register_new(isakmp_output_packet,
                                              pl->pl.n.spi_size);
              if (pl->pl.n.spi == NULL)
                return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
              memcpy(pl->pl.n.spi, isakmp_sa->cookies.initiator_cookie,
                     SSH_IKE_COOKIE_LENGTH);
              memcpy(pl->pl.n.spi + SSH_IKE_COOKIE_LENGTH,
                     isakmp_sa->cookies.responder_cookie,
                     SSH_IKE_COOKIE_LENGTH);
            }
          pl->pl.n.notification_data = hash;
          pl->pl.n.notification_data_size = hash_len;

          /* Add HASH payload instead of SIG */

          return ike_st_o_hash(isakmp_context, isakmp_input_packet,
                               isakmp_output_packet, isakmp_sa, negotiation,
                               state);
        }
#endif /* SSHDIST_IKE_XAUTH */

  ret = ike_find_private_key(isakmp_context, isakmp_sa, negotiation,
                             NULL, 0, NULL);
  if (ret != 0)
    return ret;

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  cret = ssh_private_key_get_info(negotiation->ike_ed->private_key,
                                  SSH_PKF_KEY_TYPE, &key_type, SSH_PKF_END);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("ssh_private_key_get_info failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  mac_name = NULL;
  if (strcmp(key_type, "dl-modp") == 0)
    {
      cret = ssh_private_key_select_scheme(negotiation->ike_ed->private_key,
                                           SSH_PKF_SIGN, "dsa-nist-sha1",
                                           SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_private_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      mac_name = ssh_custr("hmac-sha1");
    }
  else if (strcmp(key_type, "if-modn") == 0)
    {
      cret = ssh_private_key_select_scheme(negotiation->ike_ed->private_key,
                                           SSH_PKF_SIGN, "rsa-pkcs1-none",
                                           SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_private_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
#ifdef SSHDIST_CRYPT_ECP
  else if (strcmp(key_type, "ec-modp") == 0)
    {
      const char *scheme;
      SshIkeAttributeAuthMethValues auth_method =
        negotiation->ike_ed->attributes.auth_method;

      if (!ike_get_ecp_scheme_and_mac(auth_method,
                                      &scheme, &mac_name))
        {
          SSH_IKE_DEBUG(3, negotiation,
                      ("Unable to get the applicable private key scheme"));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      cret = ssh_private_key_select_scheme(negotiation->ike_ed->private_key,
                                          SSH_PKF_SIGN,scheme,
                                          SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_private_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
#endif /* SSHDIST_CRYPT_ECP */

  /* Check out if the previous call has finished. */
  if (negotiation->ike_ed->async_return_data_len != 0)
    {
      /* Yes, process data if we have it */
      if (negotiation->ike_ed->async_return_data)
        {
          pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                                  isakmp_sa, negotiation,
                                  SSH_IKE_PAYLOAD_TYPE_SIG);
          if (pl == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

          /* Find the size of signature */
          pl->payload_length = negotiation->ike_ed->async_return_data_len;

          /* Allocate signature buffer */
          pl->pl.sig.signature_data =
            negotiation->ike_ed->async_return_data;

          negotiation->ike_ed->async_return_data = NULL;
          negotiation->ike_ed->async_return_data_len = 0;

          /* Register allocated data */
          if (!ike_register_item(isakmp_output_packet,
                                 pl->pl.sig.signature_data))
            {
              ssh_free(pl->pl.sig.signature_data);
              return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }

          return 0;
        }
      /* Error occured during operation, return error */
      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  hash = ike_register_new(isakmp_output_packet, hash_len);
  if (hash == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, TRUE, mac_name);
  if (ret != 0)
    return ret;

  /* Some sanity cheks */
  if (ssh_private_key_max_signature_input_len(negotiation->ike_ed->
                                              private_key) !=
      (size_t) -1 &&
      ssh_private_key_max_signature_input_len(negotiation->ike_ed->
                                              private_key) < hash_len)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Hash too large, private key cannot sign it, "
                     "hash_size = %d",
                     hash_len));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Sign the digest */
  handle = ssh_private_key_sign_digest_async(negotiation->ike_ed->
                                             private_key,
                                             hash, hash_len,
                                             ike_st_o_sig_sign_cb,
                                             negotiation);

  /* Check if we started async operation, or if it is answered directly. */
  if (handle != NULL)
    {
      /* We started real async operation, go on wait */
      SSH_IKE_DEBUG(6, negotiation,
                    ("Asyncronous public key operation started"));
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  /* The result was retrieved immediately, process it now. */
  if (negotiation->ike_ed->async_return_data)
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_SIG);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Find the size of signature */
      pl->payload_length = negotiation->ike_ed->async_return_data_len;

      /* Allocate signature buffer */
      pl->pl.sig.signature_data = negotiation->ike_ed->async_return_data;

      negotiation->ike_ed->async_return_data = NULL;
      negotiation->ike_ed->async_return_data_len = 0;

      /* Register allocated data */
      if (!ike_register_item(isakmp_output_packet,
                             pl->pl.sig.signature_data))
        {
          ssh_free(pl->pl.sig.signature_data);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      return 0;
    }
  /* Error occured during operation, return error */
  negotiation->ike_ed->async_return_data = NULL;
  negotiation->ike_ed->async_return_data_len = 0;
  return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_st_o_hash
 * Append authentication hash payload.                          shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_hash(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkePacket isakmp_output_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH], *h;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  SSH_DEBUG(5, ("Start"));

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, TRUE, NULL);
  if (ret != 0)
    return ret;

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_HASH);

  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  h = ike_register_copy(isakmp_output_packet, hash, hash_len);
  if (h == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Store hash data */
  pl->payload_length = hash_len;
  pl->pl.hash.hash_data = h;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_sig_or_hash
 * Append either signature (signature authentication), or
 * hash (rsa encryption or preshared keys).                     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_sig_or_hash(SshIkeContext isakmp_context,
                                             SshIkePacket isakmp_input_packet,
                                             SshIkePacket isakmp_output_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Start, auth_method = %d", negotiation->ed->auth_method_type));
  switch (negotiation->ed->auth_method_type)
    {
    case SSH_IKE_AUTH_METHOD_ANY:
    case SSH_IKE_AUTH_METHOD_PHASE_1:
      ssh_fatal("isakmp_o_sig_or_hash: Invalid auth method for isakmp_sa: %d",
                negotiation->ed->auth_method_type);
      break;
#ifdef SSHDIST_IKE_CERT_AUTH
    case SSH_IKE_AUTH_METHOD_SIGNATURES:
      return ike_st_o_sig(isakmp_context, isakmp_input_packet,
                          isakmp_output_packet, isakmp_sa, negotiation,
                          state);
      /* NOTREACHED */
    case SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION:
      return ike_st_o_hash(isakmp_context, isakmp_input_packet,
                           isakmp_output_packet, isakmp_sa, negotiation,
                           state);
      /* NOTREACHED */
#endif /* SSHDIST_IKE_CERT_AUTH */
    case SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY:
      return ike_st_o_hash(isakmp_context, isakmp_input_packet,
                           isakmp_output_packet, isakmp_sa, negotiation,
                           state);
      /* NOTREACHED */
    }
  ssh_fatal("isakmp_o_sig_or_hash: Invalid auth method for isakmp_sa: %d",
            negotiation->ed->auth_method_type);
  /* NOTREACHED */
  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_st_o_certs_base
 * Add certificates to packet.                                  shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_certs_base(SshIkeContext isakmp_context,
                                            SshIkePacket isakmp_input_packet,
                                            SshIkePacket isakmp_output_packet,
                                            SshIkeSA isakmp_sa,
                                            SshIkeNegotiation negotiation,
                                            SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  SshIkePayload cert_pl;
  SshIkePayloadCR cr;
  int i, j;
  SshUInt32 total_crl_size, total_cert_size, max_packet_size;

  SSH_DEBUG(5, ("Start"));

  if (isakmp_input_packet == NULL ||
      negotiation->ed->auth_method_type == SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY)
    return 0;

  /* Make sure we have private key and its certificate found before we process
     certificate requests, so we can send certificate chain towards correct
     certificate */
  ret = ike_find_private_key(isakmp_context, isakmp_sa, negotiation,
                             NULL, 0, NULL);
  if (ret != 0)
    return ret;

  if (negotiation->ike_ed->own_number_of_cas == -1)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_get_certificate_authorities(negotiation->ike_pm_info,
                                             ike_policy_reply_get_cas,
                                             negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  if (negotiation->ike_ed->number_of_cas == -1)
    {
      int pkt;
      SshIkeCertificateEncodingType certificate_type, *type_table;
      unsigned char *certificate_authority, **ca_table;
      size_t certificate_authority_len, *ca_len_table;
      int number_of_cas;
      SshUInt32 number_of_cas_allocated_type;
      SshUInt32 number_of_cas_allocated_ca;
      SshUInt32 number_of_cas_allocated_ca_len;

      number_of_cas_allocated_type = 10;
      number_of_cas_allocated_ca = 10;
      number_of_cas_allocated_ca_len = 10;
      number_of_cas = 0;
      type_table = ssh_calloc(number_of_cas_allocated_type,
                              sizeof(*type_table));
      ca_table = ssh_calloc(number_of_cas_allocated_ca, sizeof(*ca_table));
      ca_len_table = ssh_calloc(number_of_cas_allocated_ca_len,
                                sizeof(*ca_len_table));
      if (type_table == NULL || ca_table == NULL || ca_len_table == NULL)
        {
        error:
          ssh_free(type_table);
          if (ca_table)
            {
              for (i = 0; i < number_of_cas_allocated_ca; i++)
                ssh_free(ca_table[i]);
              ssh_free(ca_table);
            }
          ssh_free(ca_len_table);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      for (pkt = 0; pkt < negotiation->ed->number_of_packets_in; pkt++)
        {
          pl = negotiation->ed->packets_in[pkt]->first_cr_payload;
          while (pl != NULL)
            {
              cr = &(pl->pl.cr);
              certificate_type = cr->certificate_type;
              certificate_authority = cr->certificate_authority;
              certificate_authority_len = cr->certificate_authority_len;

              if (certificate_authority_len != 0)
                {
                  if (number_of_cas == number_of_cas_allocated_type)
                    {
                      if (!ssh_recalloc(&type_table,
                                        &number_of_cas_allocated_type,
                                        number_of_cas_allocated_type + 10,
                                        sizeof(*type_table)))
                        goto error;
                    }
                  if (number_of_cas == number_of_cas_allocated_ca)
                    {
                      if (!ssh_recalloc(&ca_table,
                                        &number_of_cas_allocated_ca,
                                        number_of_cas_allocated_ca + 10,
                                        sizeof(*ca_table)))
                        goto error;
                    }
                  if (number_of_cas == number_of_cas_allocated_ca_len)
                    {
                      if (!ssh_recalloc(&ca_len_table,
                                        &number_of_cas_allocated_ca_len,
                                        number_of_cas_allocated_ca_len + 10,
                                        sizeof(*ca_len_table)))
                        goto error;
                    }
                  type_table[number_of_cas] = certificate_type;
                  ca_table[number_of_cas] =
                    ssh_memdup(certificate_authority,
                               certificate_authority_len);
                  if (ca_table[number_of_cas] == NULL)
                    goto error;
                  ca_len_table[number_of_cas] = certificate_authority_len;
                  number_of_cas++;
                }
              /* Process next certificate payload */
              pl = pl->next_same_payload;
            }
        }
      /* Did other end request any certificates? */
      if (number_of_cas == 0)
        {
          ssh_free(type_table);
          ssh_free(ca_table);
          ssh_free(ca_len_table);

          /* No, use our own CAs, if we have any */
          if (negotiation->ike_ed->own_number_of_cas > 0)
            {
              number_of_cas = negotiation->ike_ed->own_number_of_cas;
              type_table =
                ssh_memdup(negotiation->ike_ed->own_ca_encodings,
                           sizeof(SshIkeCertificateEncodingType) *
                           number_of_cas);
              ca_table = ssh_calloc(1, sizeof(unsigned char *) *
                                    number_of_cas);
              ca_len_table =
                ssh_memdup(negotiation->ike_ed->
                           own_certificate_authority_lens,
                           sizeof(size_t) * number_of_cas);
              if (type_table == NULL || ca_table == NULL ||
                  ca_len_table == NULL)
                goto error;
              for (i = 0; i < number_of_cas; i++)
                {
                  ca_table[i] = ssh_memdup(negotiation->ike_ed->
                                           own_certificate_authorities[i],
                                           negotiation->ike_ed->
                                           own_certificate_authority_lens[i]);
                  if (ca_table[i] == NULL)
                    goto error;
                }
            }
          else
            {
              /* We didn't have any ca's so return ok */
              return 0;
            }
        }
      negotiation->ike_ed->number_of_cas = number_of_cas;
      negotiation->ike_ed->ca_encodings = type_table;
      negotiation->ike_ed->certificate_authorities = ca_table;
      negotiation->ike_ed->certificate_authority_lens = ca_len_table;
    }

  if (negotiation->ike_ed->number_of_certificates == NULL)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_request_certificates(negotiation->ike_pm_info,
                                      negotiation->ike_ed->number_of_cas,
                                      negotiation->ike_ed->ca_encodings,
                                      negotiation->ike_ed->
                                      certificate_authorities,
                                      negotiation->ike_ed->
                                      certificate_authority_lens,
                                      ike_policy_reply_request_certificates,
                                      negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }

      if (negotiation->ike_ed->number_of_certificates == NULL)
        return 0;
    }


  total_crl_size = 0;
  total_cert_size = 0;
  max_packet_size = SSH_IKE_MAX_PACKET_LEN;
  for (i = 0; i < negotiation->ike_ed->number_of_cas; i++)
    {
      if (negotiation->ike_ed->number_of_certificates[i] == 0)
        {





        }
      else
        {
#ifdef SSHDIST_CERT
          SshPkcs7 pkcs7 = NULL;

          if (negotiation->ike_ed->ca_encodings[i] ==
              SSH_IKE_CERTIFICATE_ENCODING_PKCS7)
            {
              pkcs7 = ssh_pkcs7_create_signed_data(NULL, NULL);
              if (pkcs7 == NULL)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Creating pkcs7 signed data failed"));
                  continue;
                }
            }
#else /* SSHDIST_CERT */
          if (negotiation->ike_ed->ca_encodings[i] ==
              SSH_IKE_CERTIFICATE_ENCODING_PKCS7)
            {
              {
                SSH_DEBUG(SSH_D_ERROR,
                          ("PKCS #7 certificate encoding not supported"));
                continue;
              }
            }
#endif /* SSHDIST_CERT */

          for (j = 0; j < negotiation->ike_ed->number_of_certificates[i]; j++)
            {
              if ((negotiation->ed->compat_flags &
                   SSH_IKE_FLAGS_DO_NOT_SEND_CERT_CHAINS)
                  && j < (negotiation->ike_ed->number_of_certificates[i]-1))
                continue;
              if ((negotiation->ed->compat_flags &
                   SSH_IKE_FLAGS_DO_NOT_SEND_CRLS) &&
                  negotiation->ike_ed->cert_encodings[i][j] ==
                  SSH_IKE_CERTIFICATE_ENCODING_CRL)
                continue;
              if (!(negotiation->ed->compat_flags &
                    SSH_IKE_FLAGS_SEND_FULL_CHAINS))
                {
                  int ii, jj;
                  Boolean skip;

                  skip = FALSE;
                  for (ii = 0; ii < i; ii++)
                    {
                      for (jj = 0; jj < negotiation->ike_ed->
                            number_of_certificates[ii]; jj++)
                        {
                          if (negotiation->ike_ed->cert_lengths[i][j] ==
                              negotiation->ike_ed->cert_lengths[ii][jj] &&
                              memcmp(negotiation->ike_ed->certs[i][j],
                                     negotiation->ike_ed->certs[ii][jj],
                                     negotiation->ike_ed->cert_lengths[i][j])
                              == 0)
                            {
                              skip = TRUE;
                              break;
                            }
                        }
                      if (skip)
                        break;
                    }
                  if (skip)
                    continue;
                  for (jj = 0; jj < j; jj++)
                    {
                      if (negotiation->ike_ed->cert_lengths[i][j] ==
                          negotiation->ike_ed->cert_lengths[i][jj] &&
                          memcmp(negotiation->ike_ed->certs[i][j],
                                 negotiation->ike_ed->certs[i][jj],
                                 negotiation->ike_ed->cert_lengths[i][j]) == 0)
                        {
                          skip = TRUE;
                          break;
                        }
                    }
                  if (skip)
                    continue;
                }
              /* **************************************************
               * Limit the size of certificate and certificate
               * request payloads.
               *
               * CRL maximum limits
               *
               * Max CRL size is 33% of max packet size
               * Max total sum of CRL sizes is 66% of max packet size
               * Max total sum of CRLs and certs is 75% of max packet size
               *
               *
               * Cert maximum limits (except end user certificate)
               *
               * Max Cert size is 33% of max packet size
               * Max total sum of cert sizes is 75% of max packet size
               * Max total sum of CRLs and certs is 90% of max packet size
               *
               * End user certificates (last certificate)
               *
               * Max Cert size is 33% of max packet size
               * Max total sum of CRLs and certs is max packet size - 2kB
               *
               * **************************************************
               */
              if (negotiation->ike_ed->cert_lengths[i][j] >
                  max_packet_size / 3)
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Certificate or CRL not send, "
                                 "because its size exceeds %ldkB.",
                                 (unsigned long) max_packet_size / 3 / 1024));
                  continue;
                }
              if (negotiation->ike_ed->cert_encodings[i][j] ==
                  SSH_IKE_CERTIFICATE_ENCODING_CRL)
                {
                  total_crl_size += negotiation->ike_ed->cert_lengths[i][j];
                  if (total_crl_size > max_packet_size / 3 * 2)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Certificate revocation list not send, "
                                     "because total size of CRLs "
                                     "exceeds %ldkB.",
                                     (unsigned long) max_packet_size /
                                     3 * 2 / 1024));
                      total_crl_size -=
                        negotiation->ike_ed->cert_lengths[i][j];
                      continue;
                    }
                  if (total_crl_size + total_cert_size >
                      max_packet_size / 4 * 3)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Certificate revocation list not send, "
                                     "because total size of certs and CRLs "
                                     "exceeds %ldkB.",
                                     (unsigned long) max_packet_size /
                                     4 * 3 / 1024));
                      total_crl_size -=
                        negotiation->ike_ed->cert_lengths[i][j];
                      continue;
                    }
                }
              else if (j >= negotiation->ike_ed->number_of_certificates[i] - 1)
                {
                  /* End user certificate */
                  total_cert_size += negotiation->ike_ed->cert_lengths[i][j];

                  if (total_crl_size + total_cert_size >
                      max_packet_size - 2048)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("End user certificate not send, "
                                     "because total size of certs and CRLs "
                                     "exceeds %ldkB.",
                                     (unsigned long) (max_packet_size -
                                                      2048) / 1024));
                      total_cert_size -=
                        negotiation->ike_ed->cert_lengths[i][j];
                      continue;
                    }
                }
              else
                {
                  total_cert_size += negotiation->ike_ed->cert_lengths[i][j];
                  if (total_cert_size > max_packet_size / 4 * 3)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Certificate not send, because total "
                                     "size of certs exceeds %ldkB.",
                                     (unsigned long) max_packet_size / 4 *
                                     3 / 1024));
                      total_cert_size -=
                        negotiation->ike_ed->cert_lengths[i][j];
                      continue;
                    }
                  if (total_crl_size + total_cert_size >
                      max_packet_size / 10 * 9)
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Certificate not send, because total "
                                     "size of certs and CRLs exceeds %ldkB.",
                                     (unsigned long) max_packet_size / 10 *
                                     9 / 1024));
                      total_cert_size -=
                        negotiation->ike_ed->cert_lengths[i][j];
                      continue;
                    }
                }
#ifdef SSHDIST_CERT
              if (negotiation->ike_ed->ca_encodings[i] ==
                  SSH_IKE_CERTIFICATE_ENCODING_PKCS7)
                {
                  if (negotiation->ike_ed->cert_encodings[i][j] ==
                      SSH_IKE_CERTIFICATE_ENCODING_CRL ||
                      negotiation->ike_ed->cert_encodings[i][j] ==
                      SSH_IKE_CERTIFICATE_ENCODING_ARL)
                    {
                      if (ssh_pkcs7_add_crl(pkcs7,
                                            negotiation->ike_ed->certs[i][j],
                                            negotiation->ike_ed->
                                            cert_lengths[i][j])
                          != SSH_PKCS7_OK)
                        {
                          SSH_DEBUG(SSH_D_ERROR, ("Pkcs7 add crl failed"));
                        }
                    }
                  else
                    {
                      if (ssh_pkcs7_add_certificate(pkcs7,
                                                    negotiation->ike_ed->
                                                    certs[i][j],
                                                    negotiation->ike_ed->
                                                    cert_lengths[i][j])
                          != SSH_PKCS7_OK)
                        {
                          SSH_DEBUG(SSH_D_ERROR,
                                    ("Pkcs7 add certificate failed"));
                        }
                    }
                }
              else
#endif /* SSHDIST_CERT */
                {
                  cert_pl = ike_append_payload(isakmp_context,
                                               isakmp_output_packet,
                                               isakmp_sa, negotiation,
                                               SSH_IKE_PAYLOAD_TYPE_CERT);
                  if (cert_pl == NULL)
                    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

                  /* Fill it in */
                  cert_pl->pl.cert.cert_encoding =
                    negotiation->ike_ed->cert_encodings[i][j];
                  cert_pl->pl.cert.certificate_data =
                    negotiation->ike_ed->certs[i][j];
                  cert_pl->pl.cert.certificate_data_len =
                    negotiation->ike_ed->cert_lengths[i][j];
                }
            }
#ifdef SSHDIST_CERT
          if (negotiation->ike_ed->ca_encodings[i] ==
              SSH_IKE_CERTIFICATE_ENCODING_PKCS7)
            {
              cert_pl = ike_append_payload(isakmp_context,
                                           isakmp_output_packet,
                                           isakmp_sa, negotiation,
                                           SSH_IKE_PAYLOAD_TYPE_CERT);
              if (cert_pl == NULL)
                {
                  ssh_pkcs7_free(pkcs7);
                  return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
                }

              if (ssh_pkcs7_encode(pkcs7,
                                   &cert_pl->pl.cert.certificate_data,
                                   &cert_pl->pl.cert.certificate_data_len)
                  != SSH_PKCS7_OK)
                {
                  SSH_DEBUG(SSH_D_ERROR, ("Pkcs7 encode failed"));
                  cert_pl->pl.cert.certificate_data_len = 0;
                }
              cert_pl->pl.cert.cert_encoding =
                SSH_IKE_CERTIFICATE_ENCODING_PKCS7;
              ssh_pkcs7_free(pkcs7);
            }
#endif /* SSHDIST_CERT */
        }
    }
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_certs
 * Add certificate.                                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_certs(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkePacket isakmp_output_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
  /* Check if we have already sent out certificates in plain (i.e this is
     public key encryption and plain text certificates ware allowed */
  if (negotiation->ed->auth_method_type ==
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION &&
      (negotiation->ike_ed->connect_flags &
       SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS))
    return 0;
#ifdef SSHDIST_IKE_XAUTH
  if (negotiation->ike_pm_info->hybrid_client)
    return 0;
#endif /* SSHDIST_IKE_XAUTH */
  return ike_st_o_certs_base(isakmp_context, isakmp_input_packet,
                             isakmp_output_packet, isakmp_sa, negotiation,
                             state);
}


/*                                                              shade{0.9}
 * ike_st_o_optional_certs
 * Add optional plain text certificates.                        shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_optional_certs(SshIkeContext isakmp_context,
                                                SshIkePacket
                                                isakmp_input_packet,
                                                SshIkePacket
                                                isakmp_output_packet,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation,
                                                SshIkeStateMachine state)
{
  /* If exchange is something else than public key encryption, return */
  if (negotiation->ed->auth_method_type !=
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION)
    return 0;
  /* Check if plain text certificates are allowed */
  if (!(negotiation->ike_ed->connect_flags &
        SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS))
    return 0;
  return ike_st_o_certs_base(isakmp_context, isakmp_input_packet,
                             isakmp_output_packet, isakmp_sa, negotiation,
                             state);
}


/*                                                              shade{0.9}
 * ike_st_o_cr
 * Add certificate requests.                                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_cr(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkePacket isakmp_output_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  if (isakmp_context->no_cr_payloads ||
      negotiation->ed->auth_method_type == SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY)
    return 0;

  if (negotiation->ike_ed->own_number_of_cas == -1)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_get_certificate_authorities(negotiation->ike_pm_info,
                                             ike_policy_reply_get_cas,
                                             negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  for (i = 0; i < negotiation->ike_ed->own_number_of_cas; i++)
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_CR);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      pl->pl.cr.certificate_type =
        negotiation->ike_ed->own_ca_encodings[i];
      pl->pl.cr.certificate_authority_len =
        negotiation->ike_ed->own_certificate_authority_lens[i];
      pl->pl.cr.certificate_authority =
        negotiation->ike_ed->own_certificate_authorities[i];
    }
  return 0;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_st_o_vids
 * Add vendor id payloads.                                      shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_vids(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkePacket isakmp_output_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  if (negotiation->ike_ed->number_of_vids == -1)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_isakmp_request_vendor_ids(negotiation->ike_pm_info,
                                           ike_policy_reply_isakmp_vendor_ids,
                                           negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  for (i = 0; i < negotiation->ike_ed->number_of_vids; i++)
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_VID);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      pl->pl.vid.vid_data = negotiation->ike_ed->vendor_ids[i];
      pl->payload_length = negotiation->ike_ed->vendor_id_lens[i];
    }
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_get_pre_shared_key
 * Get pre shared key for skeyid calculation.                   shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_get_pre_shared_key(SshIkeContext
                                                    isakmp_context,
                                                    SshIkePacket
                                                    isakmp_input_packet,
                                                    SshIkePacket
                                                    isakmp_output_packet,
                                                    SshIkeSA isakmp_sa,
                                                    SshIkeNegotiation
                                                    negotiation,
                                                    SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  ret = ike_find_pre_shared_key(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_encrypt
 * Mark packet to be encrypted.                                 shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_encrypt(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkePacket isakmp_output_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  SSH_DEBUG(5, ("Marking encryption for packet"));
  isakmp_output_packet->flags |= SSH_IKE_FLAGS_ENCRYPTION;

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_calc_skeyid
 * Make sure we have skeyid calculated for the next packet.     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_calc_skeyid(SshIkeContext isakmp_context,
                                             SshIkePacket isakmp_input_packet,
                                             SshIkePacket isakmp_output_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  SSH_DEBUG(5, ("Calculating skeyid"));
  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_optional_encrypt
 * Mark packet to be encrypted if requested by config option.   shade{1.0}
 */

SshIkeNotifyMessageType
ike_st_o_optional_encrypt(SshIkeContext isakmp_context,
                          SshIkePacket isakmp_input_packet,
                          SshIkePacket
                          isakmp_output_packet,
                          SshIkeSA isakmp_sa,
                          SshIkeNegotiation negotiation,
                          SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  if (!(negotiation->ike_ed->connect_flags &
        SSH_IKE_IKE_FLAGS_AGGR_ENCRYPT_LAST_PACKET))
    {
      return 0;
    }
  SSH_DEBUG(5, ("Marking encryption for packet"));
  isakmp_output_packet->flags |= SSH_IKE_FLAGS_ENCRYPTION;

  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_st_o_hash_key
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_hash_key(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH], *p;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  SshIkePayloadSA sa;
  int proposal, protocol, transform;
  const unsigned char *hash_name;

  SSH_DEBUG(5, ("Hash_key start"));

  if (isakmp_context->no_key_hash_payload)
    return 0;

  sa = negotiation->ike_ed->local_sa_proposal;

  if (sa == NULL && negotiation->ike_ed->sa_i != NULL)
    sa = &(negotiation->ike_ed->sa_i->pl.sa);

  if (sa == NULL)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("No sa payload found, could not find hash information"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  hash_name = NULL;

  if (negotiation->ike_ed->attributes.hash_algorithm)
    {
      hash_name =
        ssh_custr(ssh_find_keyword_name(ssh_ike_hash_algorithms,
                                        negotiation->ike_ed->attributes.
                                        hash_algorithm));
    }
  else
    {
      for (proposal = 0; proposal < sa->number_of_proposals; proposal++)
        {
          for (protocol = 0;
              protocol < sa->proposals[proposal].number_of_protocols;
              protocol++)
            {
              SshIkePayloadPProtocol proto;
              proto = &(sa->proposals[proposal].protocols[protocol]);

              /* Check protocol id */
              if (proto->protocol_id != SSH_IKE_PROTOCOL_ISAKMP)
                continue;
              for (transform = 0;
                  transform < proto->number_of_transforms;
                  transform++)
                {
                  struct SshIkeAttributesRec attrs;
                  ssh_ike_clear_isakmp_attrs(&attrs);

                  /* Check transform id */
                  if (proto->transforms[transform].transform_id.generic !=
                      SSH_IKE_ISAKMP_TRANSFORM_KEY_IKE)
                    continue;

                  /* Read attributes */
                  if (ssh_ike_read_isakmp_attrs(negotiation,
                                                &(proto->
                                                  transforms[transform]),
                                                &attrs))
                    {
                      /* Do we have hash_algorithm */
                      if (attrs.hash_algorithm != 0)
                        {
                          /* Yes use it */
                          hash_name =
                            ssh_custr(ssh_find_keyword_name(
                                                      ssh_ike_hash_algorithms,
                                                      attrs.hash_algorithm));
                          goto out;
                        }
                    }
                }
            }
        }
    }
out:

  ret = ike_find_public_key(isakmp_context, isakmp_sa, negotiation,
                            hash, &hash_len, hash_name);
  if (ret != 0)
    return ret;

  /* Should we send hash */
  if (hash_len != 0)
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_HASH);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      p = ike_register_copy(isakmp_output_packet, hash, hash_len);
      if (p == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Store hash data */
      pl->payload_length = hash_len;
      pl->pl.hash.hash_data = p;
    }
  return 0;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_st_o_status_n
 * Add status notification payload if requested.                shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_status_n(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  SSH_DEBUG(5, ("Start"));

  if (negotiation->ike_ed->connect_flags &
      SSH_IKE_IKE_FLAGS_SEND_INITIAL_CONTACT)
    {
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_N);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      pl->pl.n.doi = SSH_IKE_DOI_IPSEC;
      pl->pl.n.protocol_id = SSH_IKE_PROTOCOL_ISAKMP;
      pl->pl.n.notify_message_type = SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT;
      if (!(negotiation->ed->compat_flags & SSH_IKE_FLAGS_USE_ZERO_SPI))
        {
          pl->pl.n.spi_size = 2 * SSH_IKE_COOKIE_LENGTH;
          pl->pl.n.spi = ike_register_new(isakmp_output_packet,
                                          pl->pl.n.spi_size);
          if (pl->pl.n.spi == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          memcpy(pl->pl.n.spi, isakmp_sa->cookies.initiator_cookie,
                 SSH_IKE_COOKIE_LENGTH);
          memcpy(pl->pl.n.spi + SSH_IKE_COOKIE_LENGTH,
                 isakmp_sa->cookies.responder_cookie,
                 SSH_IKE_COOKIE_LENGTH);
        }
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_hash_1
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_hash_1(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;

  SSH_DEBUG(5, ("Start"));
  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_HASH);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  pl->payload_length =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_a_mac));
  pl->pl.hash.hash_data = ike_register_new(isakmp_output_packet,
                                           pl->payload_length);
  if (pl->pl.hash.hash_data == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Add finalization function that will calc the hash after
     packet is encoded */
  pl->func = ike_finalize_qm_hash_1;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_hash_2
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_hash_2(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;

  SSH_DEBUG(5, ("Start"));
  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_HASH);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  pl->payload_length =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_a_mac));
  pl->pl.hash.hash_data = ike_register_new(isakmp_output_packet,
                                           pl->payload_length);
  if (pl->pl.hash.hash_data == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Add finalization function that will calc the hash after
     packet is encoded */
  pl->func = ike_finalize_qm_hash_2;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_hash_3
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_hash_3(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  SSH_DEBUG(5, ("Start"));
  ret = ike_calc_qm_hash_3(isakmp_context, isakmp_sa, negotiation,
                           NULL, hash, &hash_len);
  if (ret != 0)
    return ret;

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_HASH);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  pl->payload_length = hash_len;
  pl->pl.hash.hash_data = ike_register_copy(isakmp_output_packet,
                                            hash, hash_len);
  if (pl->pl.hash.hash_data == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_sa_proposals
 * Create output sa proposal(s) (initiator). The sa(s) comes
 * from ssh_isakmp_connect_ipsec.                               shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_sa_proposals(SshIkeContext isakmp_context,
                                                 SshIkePacket
                                                 isakmp_input_packet,
                                                 SshIkePacket
                                                 isakmp_output_packet,
                                                 SshIkeSA isakmp_sa,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  SshIkePayloadSA sa;
  int i;

  SSH_DEBUG(5, ("Start"));

  negotiation->qm_ed->sas_i =
    ssh_calloc(negotiation->qm_ed->number_of_sas, sizeof(SshIkePayload));
  if (negotiation->qm_ed->sas_i == NULL)
    {
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
    {
      /* Append payload */
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_SA);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Replace SA payload it with our own SA payload */
      memmove(&(pl->pl.sa), negotiation->qm_ed->local_sa_proposals[i],
              sizeof(struct SshIkePayloadSARec));

      /* Free local_sa_proposal and mark it empty (note the data allocated
         in the next level of sa proposal is still in use by pl.sa, and is not
         freed */
      ssh_free(negotiation->qm_ed->local_sa_proposals[i]);
      negotiation->qm_ed->local_sa_proposals[i] = NULL;

      /* Store exchange_data */
      negotiation->qm_ed->sas_i[i] = pl;

      sa = &(pl->pl.sa);

      /* First make sure the spi are registered. */
      ret = ike_st_o_sa_spi_register(isakmp_context, isakmp_output_packet, sa);
      if (ret != 0)
        return ret;
    }
  ssh_free(negotiation->qm_ed->local_sa_proposals);
  negotiation->qm_ed->local_sa_proposals = NULL;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_sa_values
 * Create sa payload with our response values for
 * other ends proposal (responder).                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_sa_values(SshIkeContext isakmp_context,
                                              SshIkePacket isakmp_input_packet,
                                              SshIkePacket
                                              isakmp_output_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkePayloadSA sa, sa_p;
  SshIkePayloadPProtocol proto, proto_p;
  SshIkePayloadT t, t_p;
  int i;
  int sel_prop, sel_trans;
  int sa_index, proto_index;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->qm_ed->selected_sas == NULL)
    {
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }

  negotiation->qm_ed->sas_r =
    ssh_calloc(negotiation->qm_ed->number_of_sas, sizeof(SshIkePayload));
  if (negotiation->qm_ed->sas_r == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  for (sa_index = 0; sa_index < negotiation->qm_ed->number_of_sas; sa_index++)
    {
      /* Find initiatior proposal */
      sa_p = &(negotiation->qm_ed->sas_i[sa_index]->pl.sa);
      sel_prop = negotiation->qm_ed->indexes[sa_index].proposal_index;
      if (sel_prop == -1)
        {
          SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable "
                              "proposal");
          return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
        }
      /* Append SA payload */
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_SA);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      /* Fill in sa payload */
      sa = &(pl->pl.sa);
      sa->doi = SSH_IKE_DOI_IPSEC;
      sa->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;

      /* Respond with only one proposal */
      sa->number_of_proposals = 1;
      sa->proposals = ssh_calloc(1, sizeof(struct SshIkePayloadPRec));
      if (sa->proposals == NULL)
        {
          sa->number_of_proposals = 0;
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      sa->proposals[0].proposal_number =
        sa_p->proposals[sel_prop].proposal_number;

      /* There can be multiple protocols in proposal */
      sa->proposals[0].number_of_protocols =
        negotiation->qm_ed->indexes[sa_index].number_of_protocols;
      sa->proposals[0].protocols =
        ssh_calloc(sa->proposals[0].number_of_protocols,
                sizeof(struct SshIkePayloadPProtocolRec));
      if (sa->proposals[0].protocols == NULL)
        {
          sa->proposals[0].number_of_protocols = 0;
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      /* Loop through all protocols */
      for (proto_index = 0;
          proto_index < sa->proposals[0].number_of_protocols;
          proto_index++)
        {
          /* Selected transform */
          sel_trans = negotiation->qm_ed->indexes[sa_index].
            transform_indexes[proto_index];

          proto = &(sa->proposals[0].protocols[proto_index]);
          proto_p = &(sa_p->proposals[sel_prop].protocols[proto_index]);
          proto->protocol_id = proto_p->protocol_id;
          /* Fill in spi information from policy manager */
          proto->spi_size =
            negotiation->qm_ed->indexes[sa_index].spi_sizes[proto_index];
          proto->spi = negotiation->qm_ed->indexes[sa_index].spis[proto_index];

          /* Only one transformation */
          proto->number_of_transforms = 1;
          proto->transforms =
            ssh_calloc(1, sizeof(struct SshIkePayloadTRec));
          if (proto->transforms == NULL)
            {
              proto->number_of_transforms = 0;
              return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }

          t = &(proto->transforms[0]);
          t_p = &(proto_p->transforms[sel_trans]);
          t->transform_number = t_p->transform_number;
          t->transform_id.generic = t_p->transform_id.generic;
          t->number_of_sa_attributes = t_p->number_of_sa_attributes;
          t->sa_attributes = ssh_calloc(t->number_of_sa_attributes,
                                        sizeof(struct SshIkeDataAttributeRec));
          if (t->sa_attributes == NULL)
            {
              t->number_of_sa_attributes = 0;
              return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }
          for (i = 0; i < t->number_of_sa_attributes; i++)
            {
              SshIkeDataAttribute attr;
              SshUInt32 value;

              /* Copy the pointers. This means we use the same storage than
                 original sa proposal */
              t->sa_attributes[i] = t_p->sa_attributes[i];
              attr = &(t->sa_attributes[i]);
              if (ssh_ike_get_data_attribute_int(attr, &value, 0))
                {
                  if (attr->attribute_type == IPSEC_CLASSES_GRP_DESC)
                    {
                      SshIkeGroupMap group;
                      group = ike_find_group(isakmp_sa, value);

                      if (negotiation->qm_ed->group == NULL)
                        negotiation->qm_ed->group = group;
                      else if (group != NULL &&
                               group != negotiation->qm_ed->group)
                        {
                          SSH_DEBUG(3, ("Several different groups found!"));
                        }
                    }
                }
            }
        }
      /* Store exchange_data */
      negotiation->qm_ed->sas_r[sa_index] = pl;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_nonce
 * Append nonce payload.                                        shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_nonce(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->qm_ed->nonce_data_len == -1)
    {
      /* Ask how much nonce data to add from policy manager */
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
      ssh_policy_qm_nonce_data_len(negotiation->qm_pm_info,
                                   ike_policy_reply_qm_nonce_data_len,
                                   negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_NONCE);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Allocate nonce buffer */
  pl->pl.nonce.nonce_data_len = negotiation->qm_ed->nonce_data_len;
  pl->pl.nonce.nonce_data = ike_register_new(isakmp_output_packet,
                                             pl->pl.nonce.nonce_data_len);
  if (pl->pl.nonce.nonce_data == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Generate random data */
  for (i = 0; i < pl->pl.nonce.nonce_data_len; i++)
    {
      pl->pl.nonce.nonce_data[i] = ssh_random_get_byte();
    }

  pl->pl.nonce.raw_nonce_packet = pl->pl.nonce.nonce_data;
  pl->payload_length = pl->pl.nonce.nonce_data_len;

  /* Store exchange_data */
  if (negotiation->qm_pm_info->this_end_is_initiator)
    negotiation->qm_ed->nonce_i = pl;
  else
    negotiation->qm_ed->nonce_r = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_ke_dh_setup_cb
 * Append Diffie-Hellman setup payload after async operation
 * is finished (ke).                                            shade{1.0}
 */

void ike_st_o_qm_ke_dh_setup_cb(SshCryptoStatus status,
                                SshPkGroupDHSecret secret,
                                const unsigned char *exchange_buffer,
                                size_t exchange_buffer_len,
                                void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->qm_ed->async_return_data =
        ssh_memdup(exchange_buffer, exchange_buffer_len);
      if (negotiation->qm_ed->async_return_data == NULL)
        {
          negotiation->qm_ed->async_return_data = NULL;
          negotiation->qm_ed->async_return_data_len = 1;
        }

      negotiation->qm_ed->async_return_data_len = exchange_buffer_len;
      negotiation->qm_ed->secret = secret;
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_pk_group_dh_setup_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->qm_ed->async_return_data = NULL;
      negotiation->qm_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_st_o_qm_optional_ke
 * If responder, add ke packet if one was provided
 * by initiator. If initiator add ke packet if wanted
 * by caller.                                                   shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_optional_ke(SshIkeContext isakmp_context,
                                                SshIkePacket
                                                isakmp_input_packet,
                                                SshIkePacket
                                                isakmp_output_packet,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation,
                                                SshIkeStateMachine state)
{
  SshIkePayload pl;
  size_t len;
  unsigned char *p;
  int i, j;
  SshOperationHandle handle;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->qm_pm_info->this_end_is_initiator)
    {
      if (!(negotiation->qm_ed->connect_flags & SSH_IKE_IPSEC_FLAGS_WANT_PFS))
        {
          SSH_IKE_DEBUG(7, negotiation, ("No PFS requested by caller"));
          return 0;
        }
    }
  else
    {
      if (negotiation->qm_ed->ke_i == NULL)
        {
          SSH_IKE_DEBUG(7, negotiation, ("No PFS requested by initiator"));
          return 0;
        }
      /* Get group descriptor from first sa proposal and first protocol,
         which provides that information. */
      if (negotiation->qm_ed->group == NULL)
        for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
          for (j = 0;
              j < negotiation->qm_ed->selected_sas[i].number_of_protocols;
              j++)
            {
              int group_desc;

              group_desc =
                negotiation->qm_ed->selected_sas[i].protocols[j].
                attributes.group_desc;
              if (group_desc != 0)
                {
                  negotiation->qm_ed->group = ike_find_group(isakmp_sa,
                                                             group_desc);
                  if (negotiation->qm_ed->group != NULL)
                    goto out;
                }
            }
    out:
      ;
    }

  if (negotiation->qm_ed->group == NULL)
    {
      SSH_IKE_DEBUG(6, negotiation, ("No group information found"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  /* Find out how much data is needed */
  len =
    ssh_pk_group_dh_setup_max_output_length(negotiation->qm_ed->group->group);

  if (len == 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No Diffie-Hellman defined for group"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  if (negotiation->qm_ed->async_return_data_len == 0)
    {
      handle =
        ssh_pk_group_dh_setup_async(negotiation->qm_ed->group->group,
                                    ike_st_o_qm_ke_dh_setup_cb,
                                    negotiation);
      /* Check if we started async operation, or if it is answered directly. */
      if (handle != NULL)
        {
          /* We started real async operation, go on wait */
          SSH_IKE_DEBUG(6, negotiation,
                        ("Asyncronous Diffie-Hellman "
                         "setup operation started"));
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
    }
  if (negotiation->qm_ed->async_return_data == NULL)
    {
      /* Error occurred during operation, return error */
      negotiation->qm_ed->async_return_data = NULL;
      negotiation->qm_ed->async_return_data_len = 0;
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  p = negotiation->qm_ed->async_return_data;
  len = negotiation->qm_ed->async_return_data_len;
  negotiation->qm_ed->async_return_data = NULL;
  negotiation->qm_ed->async_return_data_len = 0;

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_KE);
  if (pl == NULL)
    {
      ssh_free(p);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Register allocated data */
  if (!ike_register_item(isakmp_output_packet, p))
    {
      ssh_free(p);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Store the information to ke-payload */
  pl->pl.ke.key_exchange_data_len = len;
  pl->pl.ke.key_exchange_data = p;

  /* Store exchange_data */
  if (negotiation->qm_pm_info->this_end_is_initiator)
    negotiation->qm_ed->ke_i = pl;
  else
    negotiation->qm_ed->ke_r = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_optional_ids
 * Add optional ids. If initiator then ids are provided
 * by caller, if responder then ask them from
 * policy manager.                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_optional_ids(SshIkeContext isakmp_context,
                                                 SshIkePacket
                                                 isakmp_input_packet,
                                                 SshIkePacket
                                                 isakmp_output_packet,
                                                 SshIkeSA isakmp_sa,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  SSH_DEBUG(5, ("Start"));

  if (!negotiation->qm_pm_info->this_end_is_initiator)
    {
      /* Responder, ask policy manager */
      if (negotiation->qm_pm_info->local_r_id == NULL &&
          !negotiation->qm_ed->no_local_id)
        {
          /* Send query */
          negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
          ssh_policy_qm_local_id(negotiation->qm_pm_info,
                                 ike_policy_reply_qm_local_id,
                                 negotiation);

          if (negotiation->lock_flags &
              SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
            {
              /* Policy manager could not reply to query immediately. Return
                 RETRY_LATER to state machine so it will postpone processing of
                 the packet until the policy manager answers and calls callback
                 function. Clear PROCESSING_PM_QUERY flag before returning to
                 the state machine. Note that state machine will set the
                 WAITING_PM_REPLY flag. */
              negotiation->lock_flags &=
                ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
              return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
            }
        }
      if (negotiation->qm_pm_info->remote_r_id == NULL &&
          !negotiation->qm_ed->no_remote_id)
        {
          /* Send query */
          negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
          ssh_policy_qm_remote_id(negotiation->qm_pm_info,
                                  ike_policy_reply_qm_remote_id,
                                  negotiation);

          if (negotiation->lock_flags &
              SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
            {
              /* Policy manager could not reply to query immediately. Return
                 RETRY_LATER to state machine so it will postpone processing of
                 the packet until the policy manager answers and calls callback
                 function. Clear PROCESSING_PM_QUERY flag before returning to
                 the state machine. Note that state machine will set the
                 WAITING_PM_REPLY flag. */
              negotiation->lock_flags &=
                ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
              return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
            }
        }
      if (negotiation->qm_pm_info->remote_r_id != NULL)
        {
          ret = ike_st_qm_optional_id(isakmp_context, isakmp_input_packet,
                                      isakmp_output_packet, isakmp_sa,
                                      negotiation, state,
                                      negotiation->qm_pm_info->remote_r_id);
          if (ret != 0)
            return ret;
        }

      if (negotiation->qm_pm_info->local_r_id != NULL)
        {
          ret = ike_st_qm_optional_id(isakmp_context, isakmp_input_packet,
                                      isakmp_output_packet, isakmp_sa,
                                      negotiation, state,
                                      negotiation->qm_pm_info->local_r_id);
          if (ret != 0)
            return ret;
        }
    }
  else
    {
      if (negotiation->qm_pm_info->local_i_id != NULL)
        {
          ret = ike_st_qm_optional_id(isakmp_context, isakmp_input_packet,
                                      isakmp_output_packet, isakmp_sa,
                                      negotiation, state,
                                      negotiation->qm_pm_info->local_i_id);
          if (ret != 0)
            return ret;
        }
      if (negotiation->qm_pm_info->remote_i_id != NULL)
        {
          ret = ike_st_qm_optional_id(isakmp_context, isakmp_input_packet,
                                      isakmp_output_packet, isakmp_sa,
                                      negotiation, state,
                                      negotiation->qm_pm_info->remote_i_id);
          if (ret != 0)
            return ret;
        }
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_optional_responder_lifetime_n
 * Add optional responder lifetime notifications.
 * This function can only be called when we are responder.      shade{1.0}
 */

SshIkeNotifyMessageType
  ike_st_o_qm_optional_responder_lifetime_n(SshIkeContext isakmp_context,
                                            SshIkePacket isakmp_input_packet,
                                            SshIkePacket isakmp_output_packet,
                                            SshIkeSA isakmp_sa,
                                            SshIkeNegotiation negotiation,
                                            SshIkeStateMachine state)
{
  int i, j;
  SshBuffer buffer;

  SSH_DEBUG(5, ("Start"));

  buffer = NULL;

  for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
    {
      SshIkePayloadSA sa;

      /* Find our response packet back. Note that when this function is called
         the ike_st_o_qm_sa_values have already called */
      sa = &(negotiation->qm_ed->sas_r[i]->pl.sa);
      if (negotiation->qm_ed->indexes[i].expire_secs != 0 ||
          negotiation->qm_ed->indexes[i].expire_kb != 0)
        {
          SshIkePayload pl;

          if (buffer == NULL)
            buffer = ssh_buffer_allocate();

          /* There is only one proposal, take information from that, but there
             might be multiple protocols, so we need to multiply the
             notification packets to all protocols. */

          for (j = 0; j < sa->proposals[0].number_of_protocols; j++)
            {
              pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                                      isakmp_sa, negotiation,
                                      SSH_IKE_PAYLOAD_TYPE_N);
              if (pl == NULL)
                goto error;
              pl->pl.n.doi = SSH_IKE_DOI_IPSEC;
              pl->pl.n.protocol_id = sa->proposals[0].protocols[j].protocol_id;
              pl->pl.n.spi_size = sa->proposals[0].protocols[j].spi_size;
              /* No need to take copy of spi */
              pl->pl.n.spi = sa->proposals[0].protocols[j].spi;
              pl->pl.n.notify_message_type =
                SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME;
              ssh_buffer_clear(buffer);
              if (negotiation->qm_ed->indexes[i].expire_secs != 0)
                {
                  if (ssh_ike_encode_data_attribute_int(buffer,
                    IPSEC_CLASSES_SA_LIFE_TYPE, TRUE,
                    IPSEC_VALUES_LIFE_TYPE_SECONDS, 0L) == -1)
                    goto error;
                  if (ssh_ike_encode_data_attribute_int(buffer,
                    IPSEC_CLASSES_SA_LIFE_DURATION, FALSE,
                    negotiation->qm_ed->indexes[i].expire_secs, 0L) == -1)
                    goto error;
                }
              if (negotiation->qm_ed->indexes[i].expire_kb != 0)
                {
                  if (ssh_ike_encode_data_attribute_int(buffer,
                    IPSEC_CLASSES_SA_LIFE_TYPE, TRUE,
                    IPSEC_VALUES_LIFE_TYPE_KILOBYTES, 0L) == -1)
                    goto error;
                  if (ssh_ike_encode_data_attribute_int(buffer,
                    IPSEC_CLASSES_SA_LIFE_DURATION, FALSE,
                    negotiation->qm_ed->indexes[i].expire_kb, 0L) == -1)
                    goto error;
                }
              pl->pl.n.notification_data_size = ssh_buffer_len(buffer);
              pl->pl.n.notification_data =
                ike_register_copy(isakmp_output_packet,
                                  ssh_buffer_ptr(buffer),
                                  ssh_buffer_len(buffer));
              if (pl->pl.n.notification_data == NULL)
                goto error;
            }
        }
    }
  if (buffer)
    ssh_buffer_free(buffer);
  return 0;
 error:
  if (buffer)
    ssh_buffer_free(buffer);
  return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
}


/*                                                              shade{0.9}
 * ike_st_o_gen_hash
 * Add genric authentication hash payload, and add
 * finalize function to fill the hash information.              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_gen_hash(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;

  SSH_DEBUG(5, ("Start"));
  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_HASH);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  pl->payload_length =
    ssh_mac_length(ssh_mac_name(isakmp_sa->skeyid.skeyid_a_mac));
  pl->pl.hash.hash_data = ike_register_new(isakmp_output_packet,
                                           pl->payload_length);
  if (pl->pl.hash.hash_data == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Add finalization function that will calc the hash after
     packet is encoded */
  pl->func = ike_finalize_gen_hash;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_ngm_sa_proposal
 * Create output sa proposal (initiator). The sa comes
 * from ssh_isakmp_connect_ngm.                                 shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_ngm_sa_proposal(SshIkeContext isakmp_context,
                                                 SshIkePacket
                                                 isakmp_input_packet,
                                                 SshIkePacket
                                                 isakmp_output_packet,
                                                 SshIkeSA isakmp_sa,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  int proposal, protocol;
  SshIkePayloadSA sa;
  unsigned char *spi;
  size_t spi_size;

  SSH_DEBUG(5, ("Start"));

  /* Append payload */
  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_SA);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Replace SA payload it with our own SA payload */
  memmove(&(pl->pl.sa), negotiation->ngm_ed->local_sa_proposal,
          sizeof(struct SshIkePayloadSARec));

  /* Free local_sa_proposal and mark it empty (note the data allocated
     in the next level of sa proposal is still in use by pl.sa, and is not
     freed */
  ssh_free(negotiation->ngm_ed->local_sa_proposal);
  negotiation->ngm_ed->local_sa_proposal = NULL;

  /* Store exchange_data */
  negotiation->ngm_ed->sa_i = pl;

  ret = ike_st_o_sa_spi_alloc(isakmp_context, isakmp_output_packet, isakmp_sa,
                              negotiation, &spi, &spi_size);
  if (ret != 0)
    return ret;

  sa = &(pl->pl.sa);

  /* First make sure the spi are registered. */
  ret = ike_st_o_sa_spi_register(isakmp_context, isakmp_output_packet, sa);
  if (ret != 0)
    return ret;

  for (proposal = 0; proposal < sa->number_of_proposals; proposal++)
    {
      for (protocol = 0;
          protocol < sa->proposals[proposal].number_of_protocols;
          protocol++)
        {
          SshIkePayloadPProtocol proto;
          proto = &(sa->proposals[proposal].protocols[protocol]);

          /* Check protocol id */
          if (proto->protocol_id != SSH_IKE_PROTOCOL_ISAKMP)
            continue;

          if (proto->spi == NULL)
            {
              proto->spi = spi;
              proto->spi_size = spi_size;
            }
        }
    }

  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_ngm_sa_values
 * Create sa payload with our response values for
 * other ends proposal (responder).                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_ngm_sa_values(SshIkeContext isakmp_context,
                                               SshIkePacket
                                               isakmp_input_packet,
                                               SshIkePacket
                                               isakmp_output_packet,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload pl;
  SshIkePayloadSA sa, sa_p;
  SshIkePayloadPProtocol proto, proto_p;
  SshIkePayloadT t, t_p;
  int i;

  int sel_prop, sel_trans;

  SSH_DEBUG(5, ("Start"));

  /* Find initiatior proposal */
  sa_p = &(negotiation->ngm_ed->sa_i->pl.sa);
  sel_prop = negotiation->ngm_ed->selected_proposal;
  sel_trans = negotiation->ngm_ed->selected_transform;

  if (sel_prop < 0 || sel_trans < 0)
    {
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }

  pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_SA);
  if (pl == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  sa = &(pl->pl.sa);
  sa->doi = SSH_IKE_DOI_IPSEC;
  sa->situation.situation_flags = SSH_IKE_SIT_IDENTITY_ONLY;
  sa->number_of_proposals = 1;
  sa->proposals = ssh_calloc(1, sizeof(struct SshIkePayloadPRec));
  if (sa->proposals == NULL)
    {
      sa->number_of_proposals = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  sa->proposals[0].proposal_number =
    sa_p->proposals[sel_prop].proposal_number;
  sa->proposals[0].number_of_protocols = 1;
  sa->proposals[0].protocols =
    ssh_calloc(1, sizeof(struct SshIkePayloadPProtocolRec));
  if (sa->proposals[0].protocols == NULL)
    {
      sa->proposals[0].number_of_protocols = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Only one protocol */
  proto = &(sa->proposals[0].protocols[0]);
  proto_p = &(sa_p->proposals[sel_prop].protocols[0]);
  proto->protocol_id = SSH_IKE_PROTOCOL_ISAKMP;

  ret = ike_st_o_sa_spi_alloc(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              &proto->spi, &proto->spi_size);
  if (ret != 0)
    return ret;

  proto->number_of_transforms = 1;
  proto->transforms = ssh_calloc(1, sizeof(struct SshIkePayloadTRec));
  if (proto->transforms == NULL)
    {
      proto->number_of_transforms = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  t = &(proto->transforms[0]);
  t_p = &(proto_p->transforms[sel_trans]);
  t->transform_number = t_p->transform_number;
  t->transform_id.generic = t_p->transform_id.generic;
  t->number_of_sa_attributes = t_p->number_of_sa_attributes;
  t->sa_attributes = ssh_calloc(t->number_of_sa_attributes,
                                sizeof(struct SshIkeDataAttributeRec));
  if (t->sa_attributes == NULL)
    {
      t->number_of_sa_attributes = 0;
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  for (i = 0; i < t->number_of_sa_attributes; i++)
    {
      /* Copy the pointers. This means we use the same storage than original sa
         proposal */
      t->sa_attributes[i] = t_p->sa_attributes[i];
    }

  /* Store exchange_data */
  negotiation->ngm_ed->sa_r = pl;
  return 0;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * ike_st_o_cfg_attr
 * Create output attributes.                                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_cfg_attr(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  SSH_DEBUG(5, ("Start"));

  for (i = 0; i < negotiation->cfg_ed->number_of_local_attr_payloads; i++)
    {
      /* Append payload */
      pl = ike_append_payload(isakmp_context, isakmp_output_packet,
                              isakmp_sa, negotiation,
                              SSH_IKE_PAYLOAD_TYPE_ATTR);
      if (pl == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      /* Replace SA payload it with our own SA payload */
      memmove(&(pl->pl.attr), negotiation->cfg_ed->local_attrs[i],
              sizeof(struct SshIkePayloadAttrRec));

      /* Free local_attrs entry and mark it empty (note the data allocated
         in the attributes table is still in use by pl.attrs, and is not
         freed */
      ssh_free(negotiation->cfg_ed->local_attrs[i]);
      negotiation->cfg_ed->local_attrs[i] = NULL;
    }
  return 0;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


/*                                                              shade{0.9}
 * ike_st_o_rerun
 * Mark negotiation so the current packet will be
 * immediately rerunned through the state machine
 * after this step is done.                                     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_rerun(SshIkeContext isakmp_context,
                                       SshIkePacket isakmp_input_packet,
                                       SshIkePacket isakmp_output_packet,
                                       SshIkeSA isakmp_sa,
                                       SshIkeNegotiation negotiation,
                                       SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Asking for rerun"));
  return SSH_IKE_NOTIFY_MESSAGE_RETRY_NOW;
}


const char *const isakmp_xchg[] = { "None", "Base", "Identity protect",
                              "Authentication only", "Aggressive",
                              "Informal", "configuration", "7", "8", "9",
                              "10", "11", "12", "13", "14",
                              "15", "16", "17", "18", "19",
                              "20", "21", "22", "23", "24",
                              "25", "26", "27", "28", "29",
                              "30", "31", "Quick mode", "New group mode" };
const SshKeywordStruct isakmp_auth[] = {
  { "Reserved", 0 /* SSH_IKE_VALUES_AUTH_METH_RESERVED */ },
  { "Pre shared keys", SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY },
  { "DSS signatures", SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES },
  { "RSA signatures", SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES },
  { "RSA encryption", SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION },
  { "Revised RSA encryption", SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED},
#ifdef REMOVED_BY_DOI_DRAFT_07
  { "GSSAPI", SSH_IKE_VALUES_AUTH_METH_GSSAPI /* (from ike 05) */},
#endif

#ifdef SSHDIST_CRYPT_ECP
  { "ECDSA signature with SHA-256", SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256},
  { "ECDSA signature with SHA-384", SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384},
  { "ECDSA signature with SHA-512", SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521},
#endif /* SSHDIST_CRYPT_ECP */
#ifdef SSHDIST_IKE_XAUTH
  { "HybridInitDSS", SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES },
  { "HybridRespDSS", SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES },
  { "HybridInitRSA", SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES },
  { "HybridRespRSA", SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES },
  { "XAUTHInitPreShared", SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED },
  { "XAUTHRespPreShared", SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED },
  { "XAUTHInitDSS", SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES },
  { "XAUTHRespDSS", SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES },
  { "XAUTHInitRSA", SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES },
  { "XAUTHRespRSA", SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES },
  { "XAUTHInitRSAEncryption",
    SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION },
  { "XAUTHRespRSAEncryption",
    SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION },
  { "XAUTHInitRSARevisedEncryption",
    SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED },
  { "XAUTHRespRSARevisedEncryption",
    SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED },
#endif /* SSHDIST_IKE_XAUTH */
  { NULL, 0 }
};


/*                                                              shade{0.9}
 * ike_st_o_all_done
 * Print message to debug log that all done.                    shade{1.0}
 */

void ike_st_o_all_done(SshIkeContext isakmp_context,
                       SshIkeSA isakmp_sa,
                       SshIkeNegotiation negotiation)
{
  SSH_DEBUG(4, ("MESSAGE: Phase 1 { 0x%08lx %08lx - 0x%08lx %08lx } / %08x, "
                "version = %d.%d, xchg = %s, auth_method = %s, %s, "
                "cipher = %s, hash = %s, prf = %s, life = %d kB / %d sec, "
                "key len = %d, group = %d",
                (unsigned long)
                SSH_IKE_GET32(isakmp_sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(isakmp_sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(isakmp_sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(isakmp_sa->cookies.responder_cookie + 4),
                0,
                negotiation->ike_pm_info->major_version,
                negotiation->ike_pm_info->minor_version,
                isakmp_xchg[negotiation->exchange_type],
                ssh_find_keyword_name(isakmp_auth,
                                      negotiation->ike_pm_info->auth_method),
                (negotiation->ike_pm_info->this_end_is_initiator ?
                 "Initiator" : "Responder"),
                isakmp_sa->encryption_algorithm_name,
                isakmp_sa->hash_algorithm_name,
                isakmp_sa->prf_algorithm_name,
                (int) negotiation->ike_ed->attributes.life_duration_kb,
                (int) negotiation->ike_ed->attributes.life_duration_secs,
                (int) negotiation->ike_ed->attributes.key_length,
                negotiation->ike_ed->attributes.group_desc == NULL ? 0 :
                negotiation->ike_ed->attributes.group_desc->descriptor));
  SSH_IKE_DEBUG(4, negotiation,
               ("MESSAGE: Phase 1 version = %d.%d, auth_method = %s, "
                "cipher = %s, hash = %s, prf = %s, life = %d kB / %d sec, "
                "key len = %d, group = %d",
                negotiation->ike_pm_info->major_version,
                negotiation->ike_pm_info->minor_version,
                ssh_find_keyword_name(isakmp_auth,
                                      negotiation->ike_pm_info->auth_method),
                isakmp_sa->encryption_algorithm_name,
                isakmp_sa->hash_algorithm_name,
                isakmp_sa->prf_algorithm_name,
                (int) negotiation->ike_ed->attributes.life_duration_kb,
                (int) negotiation->ike_ed->attributes.life_duration_secs,
                (int) negotiation->ike_ed->attributes.key_length,
                negotiation->ike_ed->attributes.group_desc == NULL ? 0 :
                negotiation->ike_ed->attributes.group_desc->descriptor));
}


/*                                                              shade{0.9}
 * ike_st_o_wait_done
 * Mark the sa done, but wait some time for retransmits,
 * and dont free data structures before timeout is expired.     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_wait_done(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  /* Make sure we have calculated skeyid data */
  ret = ike_calc_skeyid(isakmp_context, isakmp_sa, negotiation);
  if (ret != 0)
    return ret;

  SSH_DEBUG(5, ("Marking for waiting for done"));
  isakmp_sa->phase_1_done = 1;
  ike_st_o_all_done(isakmp_context, isakmp_sa, negotiation);
  ike_debug_ike_sa_open(negotiation);

  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
  negotiation->ed->code = SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
  isakmp_sa->server_context->statistics->current_ike_sas++;
  isakmp_sa->server_context->statistics->total_ike_sas++;
  if (negotiation->ike_pm_info->this_end_is_initiator)
    {
      isakmp_sa->server_context->statistics->current_ike_sas_initiated++;
      isakmp_sa->server_context->statistics->total_ike_sas_initiated++;
    }
  else
    {
      isakmp_sa->server_context->statistics->current_ike_sas_responded++;
      isakmp_sa->server_context->statistics->total_ike_sas_responded++;
    }

  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_wait_copy_iv
 * Copy the IV from the decrypting cipher to cipher_iv.         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_copy_iv(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkePacket isakmp_output_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{
  SshCryptoStatus cret;

  /* We received last packet from the other end, we have
     copied the last bytes of the packet to cipher_iv, because
     we might fork here to multiple negotiations with different IVs */

  SSH_IKE_DEBUG_BUFFER(7, negotiation, "dec->enc iv",
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
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_o_done
 * Isakmp SA is now finished. We can now free all
 * exchange_data etc. The skeyid data is left to negotiation
 * so they can still be used. This also extracts the iv from
 * encryption/decryption cipher contexts.                       shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_done(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkePacket isakmp_output_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("ISAKMP SA negotiation done"));

  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}


/*                                                              shade{0.9}
 * ike_st_o_qm_done
 * Call callbacks, and free data structures.                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_done(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkePacket isakmp_output_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Quick Mode negotiation done"));

  /* Add delete notification */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}

/*                                                              shade{0.9}
 * ike_st_o_qm_wait_done
 * Mark the sa done, but wait some time for retransmits,
 * and dont free data structures before timeout is expired.     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_qm_wait_done(SshIkeContext isakmp_context,
                                              SshIkePacket isakmp_input_packet,
                                              SshIkePacket
                                              isakmp_output_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;

  ret = ike_qm_call_callback(isakmp_context, isakmp_input_packet,
                             isakmp_output_packet, isakmp_sa,
                             negotiation, state);
  if (ret != 0)
    return ret;

  SSH_DEBUG(5, ("Marking for waiting for done"));
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE;
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
  negotiation->ed->code = SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_o_ngm_done
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_ngm_done(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("NGM negotiation done"));
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}

/*                                                              shade{0.9}
 * ike_st_o_ngm_wait_done
 * Mark the sa done, but wait some time for retransmits,
 * and dont free data structures before timeout is expired.     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_ngm_wait_done(SshIkeContext isakmp_context,
                                               SshIkePacket
                                               isakmp_input_packet,
                                               SshIkePacket
                                               isakmp_output_packet,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Marking for waiting for done"));
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE;

  SSH_DEBUG(4, ("MESSAGE: NGM Mode wait done, adding private group %d to sa",
                negotiation->ngm_ed->attributes.group_descriptor));
  SSH_IKE_DEBUG(4, negotiation,
                ("MESSAGE: NGM Mode wait done, adding private group %d to sa",
                 negotiation->ngm_ed->attributes.group_descriptor));
  if (ike_add_group(negotiation, &negotiation->ngm_ed->attributes) == NULL)
    {
      SSH_DEBUG(3, ("ike_add_group failed"));
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
  negotiation->ed->code = SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
  return 0;
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * ike_st_o_cfg_done
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_cfg_done(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkePacket isakmp_output_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("CFG negotiation done"));
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}

/*                                                              shade{0.9}
 * ike_st_o_cfg_wait_done
 * Mark the sa done, but wait some time for retransmits,
 * and dont free data structures before timeout is expired.     shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_cfg_wait_done(SshIkeContext isakmp_context,
                                               SshIkePacket
                                               isakmp_input_packet,
                                               SshIkePacket
                                               isakmp_output_packet,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Marking for waiting for done"));
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE;

  SSH_DEBUG(4, ("MESSAGE: CFG Mode wait done"));
  SSH_IKE_DEBUG(4, negotiation, ("MESSAGE: CFG Mode wait done"));

 /* Set these to indicate that we have already seen the input packet. */
  isakmp_input_packet->first_hash_payload = NULL;
  isakmp_input_packet->first_attr_payload = NULL;

  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
  negotiation->ed->code = SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
  return 0;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * ike_st_o_n_done
 * Add callback to remove notification negotiation
 * immediately.                                                 shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_n_done(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkePacket isakmp_output_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  /* Added callback that will remove the negotiation immediately. We cannot
     free it here, because upper level functions still need the data
     structures. */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  /* Call callbacks to get statistics right. */
  ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_CONNECTED);
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, negotiation);
  ssh_xregister_timeout(0, 0, ike_remove_callback, negotiation);
  if (!isakmp_sa->phase_1_done)
    {
      /* This delete payload was sent to IKE sa that is not yet ready. Mark
         it to be waiting for delete, so it will not be considered as
         negotiation in progress */
      isakmp_sa->isakmp_negotiation->lock_flags |=
        SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE;
    }
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}


/*                                                              shade{0.9}
 * ike_st_o_d_done
 * Add callback to remove delete negotiation
 * immediately.                                                 shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_d_done(SshIkeContext isakmp_context,
                                        SshIkePacket isakmp_input_packet,
                                        SshIkePacket isakmp_output_packet,
                                        SshIkeSA isakmp_sa,
                                        SshIkeNegotiation negotiation,
                                        SshIkeStateMachine state)
{
  /* Added callback that will remove the negotiation immediately. We cannot
     free it here, because upper level functions still need the data
     structures. */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  /* Call callbacks to get statistics right. */
  ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_CONNECTED);
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, negotiation);
  ssh_xregister_timeout(0, 0, ike_remove_callback, negotiation);
  if (!isakmp_sa->phase_1_done)
    {
      /* This delete payload was sent to IKE sa that is not yet ready. Mark
         it to be waiting for delete, so it will not be considered as
         negotiation in progress */
      isakmp_sa->isakmp_negotiation->lock_flags |=
        SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE;
    }
  return SSH_IKE_NOTIFY_MESSAGE_CONNECTED;
}


/*                                                              shade{0.9}
 * ike_st_o_private
 * Process private payloads.                                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_o_private(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkePacket isakmp_output_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{
  int packet_number;

  SSH_DEBUG(5, ("Start"));

  packet_number = negotiation->ed->number_of_packets_in +
    negotiation->ed->number_of_packets_out + 1;

  /* Check if we have already processed this */
  if (negotiation->ed->packet_number == packet_number)
    return 0;

  negotiation->ed->packet_number = packet_number;

  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_IP:
    case SSH_IKE_XCHG_TYPE_AGGR:
      if (negotiation->ed->private_payload_phase_1_output)
        (*negotiation->ed->
         private_payload_phase_1_output)(negotiation->ike_pm_info,
                                         packet_number,
                                         ike_policy_reply_private_payload_out,
                                         negotiation,
                                         negotiation->ed->
                                         private_payload_context);
      else
        negotiation->lock_flags &=
          ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
    case SSH_IKE_XCHG_TYPE_QM:
      if (negotiation->ed->private_payload_phase_qm_output)
        (*negotiation->ed->
         private_payload_phase_qm_output)(negotiation->qm_pm_info,
                                          packet_number,
                                          ike_policy_reply_private_payload_out,
                                          negotiation,
                                          negotiation->ed->
                                          private_payload_context);
      else
        negotiation->lock_flags &=
          ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
    case SSH_IKE_XCHG_TYPE_NGM:
      if (negotiation->ed->private_payload_phase_2_output)
        (*negotiation->ed->
         private_payload_phase_2_output)(negotiation->ngm_pm_info,
                                         packet_number,
                                         ike_policy_reply_private_payload_out,
                                         negotiation,
                                         negotiation->ed->
                                         private_payload_context);
      else
        negotiation->lock_flags &=
          ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      if (negotiation->ed->private_payload_phase_2_output)
        (*negotiation->ed->
         private_payload_phase_2_output)(negotiation->cfg_pm_info,
                                         packet_number,
                                         ike_policy_reply_private_payload_out,
                                         negotiation,
                                         negotiation->ed->
                                         private_payload_context);
      else
        negotiation->lock_flags &=
          ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    case SSH_IKE_XCHG_TYPE_INFO:
      if (negotiation->ed->private_payload_phase_2_output)
        (*negotiation->ed->
         private_payload_phase_2_output)(negotiation->info_pm_info,
                                         packet_number,
                                         ike_policy_reply_private_payload_out,
                                         negotiation,
                                         negotiation->ed->
                                         private_payload_context);
      else
        negotiation->lock_flags &=
          ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
    default:
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      break;
    }
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of
         the packet until the policy manager answers and calls callback
         function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &=
        ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  return 0;
}
