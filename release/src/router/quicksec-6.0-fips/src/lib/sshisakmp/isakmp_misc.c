/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc isakmp routines.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshdsprintf.h"

#define SSH_DEBUG_MODULE "SshIkeMisc"

/*                                                              shade{0.9}
 * isakmp_register_item
 * Append mallocated item to packet data item array.            shade{1.0}
 */

Boolean ike_register_item(SshIkePacket packet,
                          unsigned char *ptr)
{
  if (packet->packet_data_items_alloc == 0)
    {
      packet->packet_data_items_alloc = 16;
      packet->packet_data_items = ssh_calloc(packet->packet_data_items_alloc,
                                             sizeof(unsigned char *));
      if (packet->packet_data_items == NULL)
        return FALSE;
    }
  if (packet->packet_data_items_alloc == packet->packet_data_items_cnt)
    {
      if (!ssh_recalloc(&packet->packet_data_items,
                        &packet->packet_data_items_alloc,
                        packet->packet_data_items_alloc + 16,
                        sizeof(unsigned char *)))
        return FALSE;
    }
  packet->packet_data_items[packet->packet_data_items_cnt++] = ptr;
  return TRUE;
}

/*                                                              shade{0.9}
 * ike_register_copy
 * Append memdup'ed copy of item to packet data item array.     shade{1.0}
 */

void *ike_register_copy(SshIkePacket packet,
                        unsigned char *ptr,
                        size_t len)
{
  void *new_ptr;

  new_ptr = ssh_memdup(ptr, len);
  if (new_ptr == NULL)
    return NULL;

  if (!ike_register_item(packet, new_ptr))
    {
      ssh_free(new_ptr);
      return NULL;
    }
  return new_ptr;
}

/*                                                              shade{0.9}
 * ike_register_new
 * Append callocated new item of item to packet data
 * item array.                                                  shade{1.0}
 */

void *ike_register_new(SshIkePacket packet, size_t len)
{
  void *new_ptr;

  new_ptr = ssh_calloc(1, len);
  if (new_ptr == NULL)
    return NULL;

  if (!ike_register_item(packet, new_ptr))
    {
      ssh_free(new_ptr);
      return NULL;
    }
  return new_ptr;
}

/*                                                              shade{0.9}
 * ssh_ike_check_isakmp_spi
 * Check that spi value is ok.                                  shade{1.0}
 */

SshIkeNotifyMessageType ssh_ike_check_isakmp_spi(size_t spi_size,
                                                 unsigned char *spi,
                                                 unsigned char *cookie)
{
  size_t i;

  /* If spi_size is 0 it is ok */
  if (spi_size == 0)
    {
      /* SPI ok */
      SSH_DEBUG(8, ("spi_size == 0"));
      return 0;
    }

  /* If the spi is all zeros (size doesn't matter) it is ok */
  for (i = 0; i < spi_size; i++)
    if (spi[i] != 0)
      break;
  if (i == spi_size)
    {
      /* SPI ok */
      SSH_DEBUG(8, ("spi_size == %d, data == 0", spi_size));
      return 0;
    }
  /* If the spi_size is same is cookie length and it matches the correct
     cookie, it is ok */
  if (spi_size != SSH_IKE_COOKIE_LENGTH)
    {
      SSH_DEBUG(8, ("spi_size == %d != SSH_IKE_COOKIE_LENGTH, and data != 0",
                    spi_size));
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI;
    }
  if (memcmp(spi, cookie, SSH_IKE_COOKIE_LENGTH) != 0)
    {
      SSH_DEBUG(8, ("Spi doesn't match : %08lx %08lx != %08lx %08lx",
                    (unsigned long)
                    SSH_IKE_GET32(spi),
                    (unsigned long)
                    SSH_IKE_GET32(spi + 4),
                    (unsigned long)
                    SSH_IKE_GET32(cookie),
                    (unsigned long)
                    SSH_IKE_GET32(cookie + 4)));
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI;
    }
  SSH_DEBUG(8, ("Spi match"));
  return 0;
}


/*                                                              shade{0.9}
 * ike_copy_id
 * Copy identity payload. Register data to output packet.       shade{1.0}
 */

SshIkeNotifyMessageType ike_copy_id(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_output_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkePayloadID from,
                                    SshIkePayloadID to)
{
  unsigned char **ptr;

  if (!ssh_ike_id_copy(from, to))
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ptr = NULL;
  if (to->id_type == IPSEC_ID_FQDN)
    ptr = &to->identification.fqdn;
  else if (to->id_type == IPSEC_ID_USER_FQDN)
    ptr = &to->identification.user_fqdn;
  else if (to->id_type == IPSEC_ID_DER_ASN1_DN ||
           to->id_type == IPSEC_ID_DER_ASN1_GN)
    ptr = &to->identification.asn1_data;
  else if (to->id_type == IPSEC_ID_KEY_ID)
    ptr = &to->identification.key_id;
#ifdef SSHDIST_IKE_ID_LIST
  else if (to->id_type == IPSEC_ID_LIST)
    {
      int cnt;
      int failed = 0;

      if (!ike_register_item(isakmp_output_packet,
                             (void *) to->identification.id_list_items))
        {
          failed = 2;
        }

      for (cnt = 0; cnt < to->identification.id_list_number_of_items; cnt++)
        {
          SshIkePayloadID item;

          item = &(to->identification.id_list_items[cnt]);
          if (item->id_type == IPSEC_ID_FQDN)
            ptr = &item->identification.fqdn;
          else if (item->id_type == IPSEC_ID_USER_FQDN)
            ptr = &item->identification.user_fqdn;
          else if (item->id_type == IPSEC_ID_DER_ASN1_DN ||
                   item->id_type == IPSEC_ID_DER_ASN1_GN)
            ptr = &item->identification.asn1_data;
          else if (item->id_type == IPSEC_ID_KEY_ID)
            ptr = &item->identification.key_id;
          else
            ptr = NULL;
          if (ptr)
            {
              if (failed || !ike_register_item(isakmp_output_packet, *ptr))
                {
                  ssh_free(*ptr);
                  *ptr = NULL;
                  if (!failed)
                    failed = 1;
                }
            }
        }
      if (failed == 2)
        {
          ssh_free(to->identification.id_list_items);
          to->identification.id_list_items = NULL;
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }
      if (failed)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
#endif /* SSHDIST_IKE_ID_LIST */
  else
    ptr = NULL;

  if (ptr)
    {
      if (!ike_register_item(isakmp_output_packet, *ptr))
        {
          ssh_free(*ptr);
          *ptr = NULL;
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }
    }
  return 0;
}

/*                                                              shade{0.9}
 * ike_find_group
 * Find group by group descriptor. Sa can be NULL.              shade{1.0}
 */

SshIkeGroupMap ike_find_group(SshIkeSA sa, int group)
{
  int i;
  /* Find matching group */
  for (i = 0; i < ssh_ike_groups_count; i++)
    if (group == ssh_ike_groups[i]->descriptor)
      return ssh_ike_groups[i];

  if (sa == NULL)
    return NULL;

  /* Find matching group */
  for (i = 0; i < sa->private_groups_count; i++)
    if (group == sa->private_groups[i]->descriptor)
      return sa->private_groups[i];
  return NULL;
}


/*                                                              shade{0.9}
 * ike_add_group
 * Add private group to sa structure, return NULL on error.     shade{1.0}
 */

SshIkeGroupMap ike_add_group(SshIkeNegotiation negotiation,
                             SshIkeGrpAttributes attrs)
{
  int i;
  SshPkGroup pk_grp;
  SshCryptoStatus cret;
  SshIkeSA sa = negotiation->sa;
  SshIkeContext isakmp_context;

  isakmp_context = negotiation->sa->server_context->isakmp_context;
  /* Check that the group isn't already there */
  for (i = 0; i < sa->private_groups_count; i++)
    if (attrs->group_descriptor == sa->private_groups[i]->descriptor)
      {
        SSH_IKE_DEBUG(3, negotiation, ("Private group already defined : %d",
                                      attrs->group_descriptor));
        return NULL;
      }
  if (sa->private_groups_alloc_count == sa->private_groups_count)
    {
      if (!ssh_recalloc(&sa->private_groups,
                        &sa->private_groups_alloc_count,
                        sa->private_groups_alloc_count + 10,
                        sizeof(SshIkeGroupMap)))
        return NULL;
    }
  switch (attrs->group_type)
    {
    case SSH_IKE_VALUES_GRP_TYPE_MODP:
      {
        SshMPIntegerStruct lpf[1];

        if (ike_check_prime(isakmp_context,
                            attrs->p))
          {
            ssh_mprz_init(lpf);
            ssh_mprz_set(lpf, attrs->p);
            ssh_mprz_sub_ui(lpf, lpf, 1);
            ssh_mprz_div_ui(lpf, lpf, 2);
            if (ike_check_prime(negotiation->sa->server_context->
                                isakmp_context,
                                lpf))
              {
                cret = ssh_pk_group_generate(&pk_grp,
                                             "dl-modp{dh}",
                                             SSH_PKF_PRIME_P, attrs->p,
                                             SSH_PKF_PRIME_Q, lpf,
                                             SSH_PKF_GENERATOR_G, attrs->g1,
                                             SSH_PKF_END);
              }
            else
              {
                SSH_IKE_DEBUG(3, negotiation,
                              ("lpf is not prime, group rejected"));
                cret = SSH_CRYPTO_UNSUPPORTED;
              }
            ssh_mprz_clear(lpf);
          }
        else
          {
                SSH_IKE_DEBUG(3, negotiation,
                              ("P is not prime, group rejected"));
                cret = SSH_CRYPTO_UNSUPPORTED;
          }
        break;
      }
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_GRP_TYPE_ECP:
      {
        /* Ecp group */
        if (ike_check_prime(isakmp_context, attrs->order))
          {
            cret = ssh_pk_group_generate(&pk_grp,
                                         "ec-modp",
                                         SSH_PKF_DH, "plain",
                                         SSH_PKF_PRIME_P, attrs->p,
                                         SSH_PKF_PRIME_Q, attrs->order,
                                         SSH_PKF_GENERATOR_G,
                                         attrs->g1, attrs->g2,
                                         SSH_PKF_CURVE_A, attrs->ca,
                                         SSH_PKF_CURVE_B, attrs->cb,
                                         SSH_PKF_CARDINALITY,
                                         (attrs->cardinality == NULL) ?
                                         attrs->order : attrs->cardinality,
                                         SSH_PKF_END);
          }
        else
          {
            SSH_IKE_DEBUG(3, negotiation,
                          ("Group order is not prime, group rejected"));
            cret = SSH_CRYPTO_UNSUPPORTED;
          }
      }
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      SSH_IKE_DEBUG(3, negotiation,
                    ("Isakmp add group gets unsupported type"));
      return NULL;
    }
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("ssh_pk_group_generate returned error : %s",
                     ssh_crypto_status_message(cret)));
      return NULL;
    }
  sa->private_groups[sa->private_groups_count] =
    ssh_calloc(1, sizeof(struct SshIkeGroupMapRec));
  if (sa->private_groups[sa->private_groups_count] == NULL)
    {
      ssh_pk_group_free(pk_grp);
      return NULL;
    }
  sa->private_groups[sa->private_groups_count]->isakmp_context =
    sa->server_context->isakmp_context;
  sa->private_groups[sa->private_groups_count]->descriptor =
    attrs->group_descriptor;
  sa->private_groups[sa->private_groups_count]->group = pk_grp;
#ifdef SSHDIST_EXTERNALKEY
  /* Try fetching the accelerated group, if we have accelerators defined. */
  if (isakmp_context->external_key && isakmp_context->accelerator_short_name)
    {
      SshOperationHandle handle;
      SshIkeGroupMap gmap = sa->private_groups[sa->private_groups_count];

      handle =
        ssh_ek_generate_accelerated_group(isakmp_context->external_key,
                                          isakmp_context->
                                          accelerator_short_name,
                                          pk_grp,
                                          ssh_ike_get_acc_group_cb,
                                          gmap);
      if (handle)
        gmap->accelerator_handle = handle;
    }
#endif /* SSHDIST_EXTERNALKEY */
  ssh_xregister_idle_timeout(sa->server_context->isakmp_context->
                            randomizers_private_retry, 0,
                            ike_grp_randomizers,
                            sa->private_groups[sa->private_groups_count]);
  return sa->private_groups[sa->private_groups_count++];
}

/*                                                              shade{0.9}
 * ike_remove_group
 * Remove private group to sa structure and free the grp.       shade{1.0}
 */

void ike_remove_group(SshIkeNegotiation negotiation, int group)
{
  int i;
  SshIkeSA sa = negotiation->sa;

  /* Find group */
  for (i = 0; i < sa->private_groups_count; i++)
    if (group == sa->private_groups[i]->descriptor)
      break;


  if (i == sa->private_groups_count)
    {
      SSH_DEBUG(8, ("Private group %d not found", group));
      return;
    }
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->private_groups[i]);
  ssh_pk_group_free(sa->private_groups[i]->group);
#ifdef SSHDIST_EXTERNALKEY
  if (sa->private_groups[i]->old_group)
    ssh_pk_group_free(sa->private_groups[i]->old_group);
  ssh_operation_abort(sa->private_groups[i]->accelerator_handle);
#endif /* SSHDIST_EXTERNALKEY */
  ssh_free(sa->private_groups[i]);
  if (sa->private_groups_count - 1 != i)
    memmove(&(sa->private_groups[i]),
            &(sa->private_groups[i + 1]),
            sa->private_groups_count - i - 1);
  sa->private_groups_count--;
}


/*                                                              shade{0.9}
 * ike_find_group_from_sa
 * Finds group information from sa proposal.                    shade{1.0}
 */

SshIkeNotifyMessageType ike_find_group_from_sa(SshIkeContext isakmp_context,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePayloadSA sa)
{
  int i, j, k;
  struct SshIkeAttributesRec attrs;
  struct SshIkeGrpAttributesRec grp_attrs;

  if (negotiation->ike_ed->group == NULL)
    {

      SSH_DEBUG(8, ("No isakmp group defined yet"));
      /* Get group descriptor/parameters from first sa proposal and first
         protocol, which provides that information. */
      for (i = 0; i < sa->number_of_proposals; i++)
        {
          for (j = 0; j < sa->proposals[i].number_of_protocols; j++)
            {
              for (k = 0;
                  k < sa->proposals[i].protocols[j].number_of_transforms;
                  k++)
                {
                  SshIkePayloadT trans;

                  trans = &(sa->proposals[i].protocols[j].transforms[k]);

                  ssh_ike_clear_isakmp_attrs(&attrs);
                  ssh_ike_clear_grp_attrs(&grp_attrs);

                  if (ssh_ike_read_isakmp_attrs(negotiation, trans, &attrs))
                    {
                      if (attrs.group_desc == NULL && attrs.group_parameters)
                        {
                          if (ssh_ike_read_grp_attrs(negotiation, trans,
                                                     &grp_attrs))
                            {
                              /* Insert it as group -1 */
                              ike_remove_group(negotiation, -1);
                              grp_attrs.group_descriptor = -1;
                              attrs.group_desc = ike_add_group(negotiation,
                                                               &grp_attrs);
                            }
                          ssh_ike_free_grp_attrs(&grp_attrs);
                        }
                      if (attrs.group_desc != NULL)
                        {
                          negotiation->ike_ed->group = attrs.group_desc;
                          return 0;
                        }
                    }
                }
            }
        }
      SSH_IKE_DEBUG(3, negotiation,
                    ("Could not find group information from sa_proposals"));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_append_payload
 * Append payload and return pointer to the payload
 * structure.                                                   shade{1.0}
 */

SshIkePayload ike_append_payload(SshIkeContext isakmp_context,
                                 SshIkePacket isakmp_packet,
                                 SshIkeSA isakmp_sa,
                                 SshIkeNegotiation negotiation,
                                 SshIkePayloadType type)
{
  SshIkePayload pl;
  SshIkePayload *ptr = NULL;

  if (isakmp_packet->number_of_payload_packets_allocated ==
      isakmp_packet->number_of_payload_packets)
    {
      if (!ssh_recalloc(&isakmp_packet->payloads,
                        &isakmp_packet->number_of_payload_packets_allocated,
                        isakmp_packet->number_of_payload_packets_allocated +
                        SSH_IKE_OPERATIONS_MAX,
                        sizeof(SshIkePayload)))
        return NULL;
    }
  isakmp_packet->payloads[isakmp_packet->number_of_payload_packets] =
    ssh_calloc(1, sizeof(struct SshIkePayloadRec));
  if (isakmp_packet->payloads[isakmp_packet->number_of_payload_packets]
      == NULL)
    return NULL;
  pl = isakmp_packet->payloads[isakmp_packet->number_of_payload_packets];
  isakmp_packet->number_of_payload_packets++;
  pl->type = type;
  switch (type)
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
      ssh_fatal("Internal error in ike_append_payload, got invalid "
                "payload type: %d", type);
      break;
    }
  while (*ptr != NULL)
    ptr = &((*ptr)->next_same_payload);
  *ptr = pl;
  return pl;
}


/*                                                              shade{0.9}
 * ike_st_qm_optional_id
 * Add optional id.                                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_qm_optional_id(SshIkeContext isakmp_context,
                                              SshIkePacket isakmp_input_packet,
                                              SshIkePacket
                                              isakmp_output_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkeStateMachine state,
                                              SshIkePayloadID orig_id)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload id;
  SSH_DEBUG(5, ("Start"));

  /* Append payload */
  id = ike_append_payload(isakmp_context, isakmp_output_packet,
                          isakmp_sa, negotiation, SSH_IKE_PAYLOAD_TYPE_ID);
  if (id == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ret = ike_copy_id(isakmp_context, isakmp_output_packet, isakmp_sa,
                    negotiation, orig_id, &(id->pl.id));
  if (ret != 0)
    return ret;

  ike_encode_id(isakmp_context, negotiation, id,
                &id->pl.id.raw_id_packet,
                &id->payload_length);

  /* Register the mallocated data */
  if (!ike_register_item(isakmp_output_packet, id->pl.id.raw_id_packet))
    {
      ssh_free(id->pl.id.raw_id_packet);
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_qm_dh_cb
 * Process Diffie-Hellman agree after async operation is
 * finished.                                                    shade{1.0}
 */

void ike_qm_dh_cb(SshCryptoStatus status,
                  const unsigned char *shared_secret_buffer,
                  size_t shared_secret_buffer_len,
                  void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->qm_ed->async_return_data_len = shared_secret_buffer_len;
      negotiation->qm_ed->async_return_data =
        ssh_memdup(shared_secret_buffer, shared_secret_buffer_len);
      if (negotiation->qm_ed->async_return_data == NULL)
        {
          negotiation->qm_ed->async_return_data = NULL;
          negotiation->qm_ed->async_return_data_len = 1;
        }
    }
  else
    {
      /* Signal the error case */
      SSH_IKE_DEBUG(3, negotiation,
                    ("Error in ssh_pk_group_dh_agree_async: %.200s",
                     ssh_crypto_status_message(status)));
      negotiation->qm_ed->async_return_data = NULL;
      negotiation->qm_ed->async_return_data_len = 1;
    }

  /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_qm_call_callback
 * Call SshSAHandler callback for created ipsec sa.             shade{1.0}
 */

SshIkeNotifyMessageType ike_qm_call_callback(SshIkeContext isakmp_context,
                                             SshIkePacket isakmp_input_packet,
                                             SshIkePacket isakmp_output_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state)
{
  struct SshIkeIpsecKeymatRec keymat;
#ifdef DEBUG_LIGHT
  int i, j;
#endif /* DEBUG_LIGHT */

  if (negotiation->qm_ed->nonce_i == NULL ||
      negotiation->qm_ed->nonce_r == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;

  if (negotiation->qm_ed->ke_i != NULL ||
      negotiation->qm_ed->ke_r != NULL)
    {
      SshOperationHandle handle;

      if (negotiation->qm_ed->ke_i == NULL ||
          negotiation->qm_ed->ke_r == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;

      /* We are using PFS */

      /* Calculate g^xy */
      keymat.gqmxy_size =
        ssh_pk_group_dh_agree_max_output_length(negotiation->
                                                qm_ed->group->group);
      if (keymat.gqmxy_size == 0)
        {
          SSH_DEBUG(3, ("No Diffie-Hellman defined for group"));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }

      if (negotiation->qm_ed->async_return_data_len == 0)
        {




          handle =
            ssh_pk_group_dh_agree_async(negotiation->qm_ed->group->group,
                                        negotiation->qm_ed->secret,
                                        (negotiation->qm_pm_info->
                                         this_end_is_initiator ?
                                         negotiation->qm_ed->ke_r->
                                         pl.ke.key_exchange_data :
                                         negotiation->qm_ed->ke_i->
                                         pl.ke.key_exchange_data),
                                        (negotiation->qm_pm_info->
                                         this_end_is_initiator ?
                                         negotiation->qm_ed->ke_r->
                                         pl.ke.key_exchange_data_len:
                                         negotiation->qm_ed->ke_i->
                                         pl.ke.key_exchange_data_len),
                                        ike_qm_dh_cb,
                                        negotiation);
          negotiation->qm_ed->secret = NULL;
          /* Check if we started async operation, or if it is answered
             directly. */
          if (handle != NULL)
            {
              /* We started real async operation, go on wait */
              SSH_IKE_DEBUG(6, negotiation,
                            ("Asyncronous Diffie-Hellman agree operation "
                             "started"));
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

      keymat.gqmxy = negotiation->qm_ed->async_return_data;
      keymat.gqmxy_size = negotiation->qm_ed->async_return_data_len;
      negotiation->qm_ed->async_return_data = NULL;
      negotiation->qm_ed->async_return_data_len = 0;

      SSH_IKE_DEBUG_BUFFER(6, negotiation, "Diffie-hellman secret g^(qm)xy",
                           keymat.gqmxy_size, keymat.gqmxy);
    }
  else
    {
      keymat.gqmxy_size = 0;
      keymat.gqmxy = NULL;
    }

  keymat.skeyid_d_size = isakmp_sa->skeyid.skeyid_d_size;
  keymat.skeyid_d = isakmp_sa->skeyid.skeyid_d;
  keymat.skeyid_d_mac_alg = isakmp_sa->prf_algorithm_name;
  keymat.ni_size = negotiation->qm_ed->nonce_i->pl.nonce.nonce_data_len;
  keymat.ni = negotiation->qm_ed->nonce_i->pl.nonce.nonce_data;

  keymat.nr_size = negotiation->qm_ed->nonce_r->pl.nonce.nonce_data_len;
  keymat.nr = negotiation->qm_ed->nonce_r->pl.nonce.nonce_data;

  SSH_IKE_DEBUG(4, negotiation,
                ("MESSAGE: Phase 2 connection succeeded, %s, group = %d",
                 (keymat.gqmxy == NULL ? "No PFS" : "Using PFS"),
                 negotiation->qm_ed->group == NULL ? 0 :
                 negotiation->qm_ed->group->descriptor));
  SSH_DEBUG(4, ("MESSAGE: Phase 2 connection succeeded, %s, group = %d",
                (keymat.gqmxy == NULL ? "No PFS" : "Using PFS"),
                negotiation->qm_ed->group == NULL ? 0 :
                negotiation->qm_ed->group->descriptor));
#ifdef DEBUG_LIGHT
  for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
    for (j = 0;
        j < negotiation->qm_ed->selected_sas[i].number_of_protocols;
        j++)
      {
        SshIkeIpsecAttributes attrs;
        unsigned char *proto;
        const char *temp, *auth, *encap, *longseq;

        attrs = &(negotiation->qm_ed->selected_sas[i].protocols[j].attributes);
        switch (negotiation->qm_ed->selected_sas[i].protocols[j].protocol_id)
          {
          case SSH_IKE_PROTOCOL_IPSEC_AH:
            temp = ssh_find_keyword_name(ssh_ike_ipsec_ah_transforms,
                                         negotiation->qm_ed->selected_sas[i].
                                         protocols[j].transform_id.generic);
            if (temp == NULL)
              ssh_dsprintf(&proto, "Unknown AH %d",
                           negotiation->qm_ed->selected_sas[i].
                           protocols[j].transform_id.generic);
            else
              ssh_dsprintf(&proto, "AH %s", temp);
            break;
          case SSH_IKE_PROTOCOL_IPSEC_ESP:
            temp = ssh_find_keyword_name(ssh_ike_ipsec_esp_transforms,
                                         negotiation->qm_ed->selected_sas[i].
                                         protocols[j].transform_id.generic);
            if (temp == NULL)
              ssh_dsprintf(&proto, "Unknown ESP %d",
                           negotiation->qm_ed->selected_sas[i].
                           protocols[j].transform_id.generic);
            else
              ssh_dsprintf(&proto, "ESP %s", temp);
            break;
          case SSH_IKE_PROTOCOL_IPCOMP:
            temp = ssh_find_keyword_name(ssh_ike_ipsec_ipcomp_transforms,
                                         negotiation->qm_ed->selected_sas[i].
                                         protocols[j].transform_id.generic);
            if (temp == NULL)
              ssh_dsprintf(&proto, "Unknown IPCOMP %d",
                           negotiation->qm_ed->selected_sas[i].
                           protocols[j].transform_id.generic);
            else
              ssh_dsprintf(&proto, "IPCOMP %s", temp);
            break;
          default:
            ssh_dsprintf(&proto, "Unknown proto %d, id = %d",
                         negotiation->qm_ed->selected_sas[i].
                         protocols[j].protocol_id,
                         negotiation->qm_ed->selected_sas[i].
                         protocols[j].transform_id.generic);
            break;
          }
        auth = ssh_find_keyword_name(ssh_ike_ipsec_auth_algorithms,
                                     attrs->auth_algorithm);
        if (auth == NULL)
          auth = "Auth not set";

        encap = ssh_find_keyword_name(ssh_ike_ipsec_encapsulation_modes,
                                      attrs->encapsulation_mode);
        if (encap == NULL)
          encap = "Encapsulation not set";

        longseq = ssh_find_keyword_name(ssh_ike_ipsec_longseq_values,
                                        attrs->longseq_size);
        if (longseq == NULL)
          longseq = "Extended seq not used";

        SSH_IKE_DEBUG(4,  negotiation,
                      ("MESSAGE: SA[%d][%d] = %s, life = %d kB/%d sec, "
                       "group = %d, %s, %s, %s, key len = %d, key rounds = %d",
                       i, j, proto,
                       (int) attrs->life_duration_kb,
                       (int) attrs->life_duration_secs,
                       attrs->group_desc,
                       encap, auth, longseq,
                       attrs->key_length,
                       attrs->key_rounds));
        SSH_DEBUG(4, ("MESSAGE: SA[%d][%d] = %s, life = %d kB/%d sec, "
                      "group = %d, %s, %s, %s, key len = %d, key rounds = %d",
                      i, j, proto,
                      (int) attrs->life_duration_kb,
                      (int) attrs->life_duration_secs,
                      attrs->group_desc,
                      encap, auth, longseq,
                      attrs->key_length,
                      attrs->key_rounds));

        ssh_free(proto);
      }
#endif /* DEBUG_LIGHT */

  /* Update life duration information */
  negotiation->qm_ed->selected_sas->life_duration_secs =
    negotiation->qm_pm_info->sa_expire_timer_sec;
  negotiation->qm_ed->selected_sas->life_duration_kb =
    negotiation->qm_pm_info->sa_expire_timer_kb;

  isakmp_sa->statistics.created_suites += negotiation->qm_ed->number_of_sas;

  (*isakmp_sa->server_context->
   sa_callback)(negotiation,
                negotiation->qm_pm_info,
                negotiation->qm_ed->number_of_sas,
                negotiation->qm_ed->selected_sas,
                &keymat,
                isakmp_sa->server_context->sa_callback_context);
  if (keymat.gqmxy != NULL)
    {
      memset(keymat.gqmxy, 0, keymat.gqmxy_size);
      ssh_free(keymat.gqmxy);
    }
  return 0;
}

#ifdef SSHDIST_CRYPT_ECP
/*
 * ike_get_ecp_scheme
 * Select the appropriate scheme for ecp key based on its size.
 */

Boolean ike_get_ecp_scheme_and_mac(SshIkeAttributeAuthMethValues auth_method,
                                   const char ** scheme,
                                   const unsigned char **mac_name)
{
  const char *sig_scheme = NULL;
  const char *mac = NULL;
  Boolean rv = FALSE;

  switch (auth_method)
    {
#ifdef SSHDIST_CRYPT_SHA256
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
      sig_scheme = "dsa-none-sha256";
      mac = "hmac-sha256";
      break;
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
      sig_scheme = "dsa-none-sha384";
      mac = "hmac-sha384";
      break;
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
      sig_scheme = "dsa-none-sha512";
      mac = "hmac-sha512";
      break;
#endif /* SSHDIST_CRYPT_SHA512 */
    default:
      SSH_DEBUG(SSH_D_ERROR,
                ("Invalid ECP authentication method id: %d",
                 (int) auth_method));
      break;
    }

  *scheme = sig_scheme;
  *mac_name = ssh_custr(mac);

  if ((sig_scheme != NULL) && (mac != NULL))
    rv = TRUE;

  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */


