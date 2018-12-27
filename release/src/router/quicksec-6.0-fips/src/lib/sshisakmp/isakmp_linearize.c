/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp library linearize (import / export) code.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "isakmp_linearize.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshIkeLinearize"

/* Expore identity payload to buffer. Buffer is NOT cleared, before the
   export. Returns size of the data added to the buffer, or 0 in case of error.
   In case of error the data added to the buffer is removed. */
size_t ssh_ike_sa_export_id(SshBuffer buffer, SshIkePayloadID id)
{
  size_t orig_len;
  size_t item_len;
  size_t len;

  SSH_DEBUG(5, ("Start"));

  orig_len = ssh_buffer_len(buffer);
  len = 0;
  if (id == NULL)
    {
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_UINT32((SshUInt32) 0),
         SSH_FORMAT_END);
      if (item_len == 0)
        goto error;
      len += item_len;
      return len;
    }
  item_len = ssh_encode_buffer
    (buffer,
     SSH_ENCODE_UINT32((SshUInt32) id->id_type),
     SSH_ENCODE_UINT32((SshUInt32) id->protocol_id),
     SSH_ENCODE_UINT32((SshUInt32) id->port_number),
     SSH_ENCODE_UINT32((SshUInt32) id->port_range_end),
     SSH_FORMAT_END);
  if (item_len == 0)
    goto error;
  len += item_len;
  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv4_addr, 4),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_FQDN:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_UINT32_STR(id->identification.fqdn,
         id->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_USER_FQDN:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_UINT32_STR(id->identification.user_fqdn,
         id->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv4_addr_subnet, 4),
         SSH_ENCODE_DATA(id->identification.ipv4_addr_netmask, 4),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV6_ADDR:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv6_addr, 16),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv6_addr_subnet, 16),
         SSH_ENCODE_DATA(id->identification.ipv6_addr_netmask, 16),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv4_addr_range1, 4),
         SSH_ENCODE_DATA(id->identification.ipv4_addr_range2, 4),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_DATA(id->identification.ipv6_addr_range1, 16),
         SSH_ENCODE_DATA(id->identification.ipv6_addr_range2, 16),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_UINT32_STR(id->identification.asn1_data,
         id->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_KEY_ID:
      item_len = ssh_encode_buffer
        (buffer,
         SSH_ENCODE_UINT32_STR(id->identification.key_id,
         id->identification_len),
         SSH_FORMAT_END);
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        int cnt;

        item_len = ssh_encode_buffer(buffer,
                                     SSH_ENCODE_UINT32(
                                     (SshUInt32) id->identification.
                                     id_list_number_of_items),
                                     SSH_FORMAT_END);
        if (item_len == 0)
          goto error;
        len += item_len;
        for (cnt = 0;
             cnt < id->identification.id_list_number_of_items;
             cnt++)
          {
            item_len =
              ssh_ike_sa_export_id(buffer,
                                   &(id->identification.id_list_items[cnt]));
            if (item_len == 0)
              goto error;
            len += item_len;
          }
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    }
  if (item_len == 0)
    goto error;
  len += item_len;
  return len;
 error:
  item_len = ssh_buffer_len(buffer);
  if ((item_len - orig_len) != 0)
    ssh_buffer_consume_end(buffer, (item_len - orig_len));
  return 0;
}

/* Export given IKE SA pointed by negotiation to buffer. Buffer is NOT cleared
   before the export. Returns size of packet added to the buffer, or 0 in case
   of error. In case of error the data added to the buffer is removed. */
size_t ssh_ike_sa_export(SshBuffer buffer, SshIkeNegotiation negotiation)
{
  SshIkeNegotiation ike_negotiation;
  SshIkePMPhaseI pm_info;
  SshIkeSA sa;
  size_t orig_len;
  size_t item_len;
  size_t len;

  SSH_DEBUG(5, ("Start"));

  orig_len = ssh_buffer_len(buffer);
  len = 0;

  sa = negotiation->sa;
  if (sa == NULL)
    {
      SSH_DEBUG(3, ("Trying to export SA that is deleted"));
      goto error;
    }
  if (sa->lock_flags != 0)
    {
      SSH_DEBUG(3, ("Trying to export SA whose lock_flags is not 0"));
      goto error;
    }
  if (!sa->phase_1_done)
    {
      SSH_DEBUG(3, ("Trying to export IKE SA which is not ready yet"));
      goto error;
    }

  ike_negotiation = sa->isakmp_negotiation;
  pm_info = ike_negotiation->ike_pm_info;

  if (ike_negotiation->notification_state !=
      SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
    {
      SSH_DEBUG(3, ("Trying to export IKE SA which hasn't call callback yet"));
      goto error;
    }
  if ((ike_negotiation->lock_flags & ~SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE)
      != 0)
    {
      SSH_DEBUG(3, ("Trying to export IKE SA whose neg lock_flags are not 0"));
      goto error;
    }

  item_len = ssh_encode_buffer
    (buffer,
     /* Magic number */
     SSH_ENCODE_UINT32((SshUInt32) SSH_IKE_EXPORT_MAGIC1),
     /* Version number */
     SSH_ENCODE_UINT32((SshUInt32) SSH_IKE_EXPORT_VERSION),
     /* Cookies, initiator, responder */
     SSH_ENCODE_DATA(sa->cookies.initiator_cookie, SSH_IKE_COOKIE_LENGTH),
     SSH_ENCODE_DATA(sa->cookies.responder_cookie, SSH_IKE_COOKIE_LENGTH),
     /* Local ip, port. */
     SSH_ENCODE_UINT32_STR(
       pm_info->local_ip, ssh_ustrlen(pm_info->local_ip)),
     SSH_ENCODE_UINT32_STR(
       pm_info->local_port, ssh_ustrlen(pm_info->local_port)),
     /* Remote ip, port. */
     SSH_ENCODE_UINT32_STR(
       pm_info->remote_ip, ssh_ustrlen(pm_info->remote_ip)),
     SSH_ENCODE_UINT32_STR(
       pm_info->remote_port, ssh_ustrlen(pm_info->remote_port)),
     /* IKE exchange version. */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->major_version),
     SSH_ENCODE_UINT32((SshUInt32) pm_info->minor_version),
     /* IKE exchange type. */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->exchange_type),
     /* Was this the initiator for the original exchange? */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->this_end_is_initiator),
     /* Byte count and byte limit. */
     SSH_ENCODE_UINT64((SshUInt64) sa->byte_count),
     SSH_ENCODE_UINT64((SshUInt64) sa->kbyte_limit),
     /* Created time and laste use time */
     SSH_ENCODE_UINT64((SshUInt64) sa->created_time),
     SSH_ENCODE_UINT64((SshUInt64) sa->last_use_time),
     /* Encryption, hash, prf algorithm names. */
     SSH_ENCODE_UINT32_STR(sa->encryption_algorithm_name,
     ssh_ustrlen(sa->encryption_algorithm_name)),
     SSH_ENCODE_UINT32_STR(sa->hash_algorithm_name,
     ssh_ustrlen(sa->hash_algorithm_name)),
     SSH_ENCODE_UINT32_STR(sa->prf_algorithm_name,
     ssh_ustrlen(sa->prf_algorithm_name)),
     /* Cipher key. */
     SSH_ENCODE_UINT32_STR(sa->cipher_key, sa->cipher_key_len),
     /* Cipher IV. */
     SSH_ENCODE_UINT32_STR(sa->cipher_iv, sa->cipher_iv_len),
     /* Keying material, Diffie-Hellman. */
     SSH_ENCODE_UINT32_STR(sa->skeyid.dh, sa->skeyid.dh_size),
     /* Keying material, SKEYID mac. */
     SSH_ENCODE_UINT32_STR(sa->skeyid.skeyid, sa->skeyid.skeyid_size),
     /* Keying material, SKEYID_d mac. */
     SSH_ENCODE_UINT32_STR(sa->skeyid.skeyid_d, sa->skeyid.skeyid_d_size),
     /* Keying material, SKEYID_a mac. */
     SSH_ENCODE_UINT32_STR(sa->skeyid.skeyid_a, sa->skeyid.skeyid_a_size),
     /* Keying material, SKEYID_e mac. */
     SSH_ENCODE_UINT32_STR(sa->skeyid.skeyid_e, sa->skeyid.skeyid_e_size),
     /* Retry defaults. */
     SSH_ENCODE_UINT32(sa->retry_limit),
     SSH_ENCODE_UINT32(sa->retry_timer),
     SSH_ENCODE_UINT32(sa->retry_timer_usec),
     SSH_ENCODE_UINT32(sa->retry_timer_max),
     SSH_ENCODE_UINT32(sa->retry_timer_max_usec),
     SSH_ENCODE_UINT32(sa->expire_timer),
     SSH_ENCODE_UINT32(sa->expire_timer_usec),
     /* Statistics. */
     SSH_ENCODE_UINT32(sa->statistics.packets_in),
     SSH_ENCODE_UINT32(sa->statistics.packets_out),
     SSH_ENCODE_UINT32(sa->statistics.octects_in),
     SSH_ENCODE_UINT32(sa->statistics.octects_out),
     SSH_ENCODE_UINT32(sa->statistics.created_suites),
     SSH_ENCODE_UINT32(sa->statistics.deleted_suites),
     /* IKE SA negotiation information. */
     SSH_ENCODE_UINT32((SshUInt32) ike_negotiation->exchange_type),
     /* This field used to be in negotation structure, now it is in
        ExchangeData strcuture which is already freed. Put the copy of the
        value from pm_info here to be compatible with old versions. */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->auth_method_type),





     SSH_ENCODE_UINT32((SshUInt32) 0),
     /* Private groups as UINT32_STRING. */



     SSH_ENCODE_UINT32_STR(ssh_ustr(""), 0),
     SSH_FORMAT_END);
  if (item_len == 0)
    goto error;
  len += item_len;

  /* Local id. */
  item_len = ssh_ike_sa_export_id(buffer, pm_info->local_id);
  if (item_len == 0)
    goto error;
  len += item_len;

  /* Remote id. */
  item_len = ssh_ike_sa_export_id(buffer, pm_info->remote_id);
  if (item_len == 0)
    goto error;
  len += item_len;

  item_len = ssh_encode_buffer
    (buffer,
     /* Authentication type. */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->auth_method_type),
     SSH_ENCODE_UINT32((SshUInt32) pm_info->auth_method),
     /* Start and expire times. */
     SSH_ENCODE_UINT64((SshUInt64) pm_info->sa_start_time),
     SSH_ENCODE_UINT64((SshUInt64) pm_info->sa_expire_time),
     /* None of the policy manager filled data is copied, this include
        auth_data, auth_data_len, own_auth_data, own_auth_data_len,
        public_key, number_of_certificates, number_of_allocated_certificates,
        certificates, certificate_lens, certificate_encodings,
        policy_manager_data, pm. */
     SSH_ENCODE_UINT32((SshUInt32) pm_info->doi),
     /* Magic number */
     SSH_ENCODE_UINT32((SshUInt32) SSH_IKE_EXPORT_MAGIC2),
     SSH_FORMAT_END);
  if (item_len == 0)
    goto error;
  len += item_len;
  return len;
 error:
  item_len = ssh_buffer_len(buffer);
  if ((item_len - orig_len) != 0)
    ssh_buffer_consume_end(buffer, (item_len - orig_len));
  return 0;
}

/* Import id from the buffer and store newly allocated id to the id pointer,
   freeing the old id if such was stored there. If the id_txt pointer is given
   then it is used to store the textual format of the id. If that pointer
   contained old id string it is freed before the new string stored there.
   Returns TRUE if successful and FALSE otherwise. In case of error the buffer
   is left unspecified state (i.e part of it might be consumed). */
Boolean ssh_ike_sa_import_id(SshBuffer buffer, SshIkePayloadID *id,
                             char **id_txt)
{
  SshUInt32 a32, b32, c32;
  SshIkePayloadID newp = NULL;
  char newp_txt[255];
  size_t ret = 0;

  SSH_DEBUG(5, ("Start"));

  if (ssh_decode_buffer
      (buffer,
       SSH_DECODE_UINT32(&a32),
       SSH_FORMAT_END) == 0)
    goto error;

  if (a32 == 0)
    {
      if (id)
        {
          ssh_ike_id_free(*id);
          *id = NULL;
        }
      if (id_txt)
        {
          ssh_free(*id_txt);
          *id_txt = ssh_strdup("No Id");
          if (*id_txt == NULL)
            return FALSE;
        }
      return TRUE;
    }

  newp = ssh_malloc(sizeof(*newp));
  if (newp == NULL)
    return FALSE;

  newp->raw_id_packet = NULL;

  newp->id_type = a32;

  if (ssh_decode_buffer
      (buffer,
       SSH_DECODE_UINT32(&a32),
       SSH_DECODE_UINT32(&b32),
       SSH_DECODE_UINT32(&c32),
       SSH_FORMAT_END) == 0)
    goto error;

  newp->protocol_id = a32;
  newp->port_number = b32;
  newp->port_range_end = c32;

  switch (newp->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv4_addr, 4),
         SSH_FORMAT_END);
      newp->identification_len = 4;
      break;
    case IPSEC_ID_FQDN:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_UINT32_STR(&newp->identification.fqdn,
         &newp->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_USER_FQDN:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_UINT32_STR(&newp->identification.user_fqdn,
         &newp->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv4_addr_subnet, 4),
         SSH_DECODE_DATA(newp->identification.ipv4_addr_netmask, 4),
         SSH_FORMAT_END);
      newp->identification_len = 8;
      break;
    case IPSEC_ID_IPV6_ADDR:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv6_addr, 16),
         SSH_FORMAT_END);
      newp->identification_len = 16;
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv6_addr_subnet, 16),
         SSH_DECODE_DATA(newp->identification.ipv6_addr_netmask, 16),
         SSH_FORMAT_END);
      newp->identification_len = 32;
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv4_addr_range1, 4),
         SSH_DECODE_DATA(newp->identification.ipv4_addr_range2, 4),
         SSH_FORMAT_END);
      newp->identification_len = 8;
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_DATA(newp->identification.ipv6_addr_range1, 16),
         SSH_DECODE_DATA(newp->identification.ipv6_addr_range2, 16),
         SSH_FORMAT_END);
      newp->identification_len = 32;
      break;
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_UINT32_STR(&newp->identification.asn1_data,
         &newp->identification_len),
         SSH_FORMAT_END);
      break;
    case IPSEC_ID_KEY_ID:
      ret = ssh_decode_buffer
        (buffer,
         SSH_DECODE_UINT32_STR(&newp->identification.key_id,
         &newp->identification_len),
         SSH_FORMAT_END);
      break;
#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      {
        int cnt;
        SshIkePayloadID itemp = NULL;

        newp->identification_len = 0;
        ret = ssh_decode_buffer
          (buffer,
           SSH_DECODE_UINT32((SshUInt32 *)&newp->identification.
                             id_list_number_of_items),
           SSH_FORMAT_END);
        if (ret == 0)
          goto error;
        newp->identification.id_list_items =
          ssh_calloc(newp->identification.id_list_number_of_items,
                     sizeof(newp->identification.id_list_items[0]));
        if (newp->identification.id_list_items == NULL)
          goto error;

        for (cnt = 0;
             cnt < newp->identification.id_list_number_of_items;
             cnt++)
          {
            if (!ssh_ike_sa_import_id(buffer, &itemp, NULL))
              goto error;

            newp->identification.id_list_items[cnt] = *itemp;
            ssh_free(itemp);
            itemp = NULL;
          }
        break;
      }
#endif /* SSHDIST_IKE_ID_LIST */
    }
  if (ret == 0)
    goto error;
  if (id_txt)
    {
      ssh_free(*id_txt);
      ssh_ike_id_to_string(newp_txt, sizeof(newp_txt), newp);
      *id_txt = ssh_strdup(newp_txt);
      if (*id_txt == NULL)
        goto error;
    }
  if (id)
    {
      ssh_ike_id_free(*id);
      *id = newp;
    }
  else
    {
      ssh_ike_id_free(newp);
    }
  return TRUE;
 error:
  if (newp != NULL)
    ssh_ike_id_free(newp);
  return FALSE;
}


/* Import given buffer to the IKE Server given in the argument. Returns the IKE
   SA negotiation or NULL in case of error. The data that was parsed
   successfully is consumed from the buffer in any case. If there is extra data
   after the complete packet then it is left to the buffer. */
SshIkeNegotiation ssh_ike_sa_import(SshBuffer buffer,
                                    SshIkeServerContext server)
{
  unsigned char initiator_cookie[SSH_IKE_COOKIE_LENGTH];
  unsigned char responder_cookie[SSH_IKE_COOKIE_LENGTH];
  unsigned char *auc, *buc, *cuc, *duc;
  SshUInt32 a32, b32, c32, d32;
  SshUInt64 a64, b64, c64, d64;
  SshIkePMPhaseI pm_info;
  SshIkeNegotiation neg;
  SshIkeSA sa;
  size_t len;
  long l;
  SshADTHandle h;
  SshCryptoStatus cret;
  SshTime t;
  SshUInt16 local_port;

  sa = NULL;
  pm_info = NULL;
  neg = NULL;
  auc = NULL;
  buc = NULL;
  cuc = NULL;
  duc = NULL;

  SSH_DEBUG(5, ("Start"));

  len = ssh_decode_buffer
    (buffer,
     /* Magic number */
     SSH_DECODE_UINT32(&a32),
     /* Version number */
     SSH_DECODE_UINT32(&b32),
     /* Cookies, initiator, responder */
     SSH_DECODE_DATA(initiator_cookie, SSH_IKE_COOKIE_LENGTH),
     SSH_DECODE_DATA(responder_cookie, SSH_IKE_COOKIE_LENGTH),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode magic, version, cookies"));
      goto error;
    }
  if (a32 != SSH_IKE_EXPORT_MAGIC1)
    {
      SSH_DEBUG(3, ("Invalid magic 0x%08x vs 0x%08x", (int) a32,
                    SSH_IKE_EXPORT_MAGIC1));
      goto error;
    }
  if (b32 != SSH_IKE_EXPORT_VERSION)
    {
      SSH_DEBUG(3, ("Invalid version 0x%08x vs 0x%08x", (int) b32,
                    SSH_IKE_EXPORT_VERSION));
      goto error;
    }

  h = ssh_adt_get_handle_to_equal(server->isakmp_context->
                                  isakmp_cookie_mapping, initiator_cookie);
  if (h != SSH_ADT_INVALID)
    {
      SSH_DEBUG(3, ("Duplicate initiator cookie"));
      goto error;
    }

  sa = ike_sa_allocate(server, initiator_cookie, responder_cookie);
  if (sa == NULL)
    {
      SSH_DEBUG(3, ("ike_sa_allocate_half return error"));
      goto error;
    }

  len = ssh_decode_buffer
    (buffer,
     /* Local ip, port. */
     SSH_DECODE_UINT32_STR(&auc, NULL),
     SSH_DECODE_UINT32_STR(&buc, NULL),
     /* Remote ip, port. */
     SSH_DECODE_UINT32_STR(&cuc, NULL),
     SSH_DECODE_UINT32_STR(&duc, NULL),
     /* IKE exchange version. */
     SSH_DECODE_UINT32(&a32),
     SSH_DECODE_UINT32(&b32),
     /* IKE exchange type. */
     SSH_DECODE_UINT32(&c32),
     /* Was this the initiator for the original exchange? */
     SSH_DECODE_UINT32(&d32),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode ip, port, version, exchage type, init"));
      goto error;
    }
  if (!ike_init_isakmp_sa(sa, auc, buc, cuc, duc, a32, b32, c32, d32, FALSE))
    {
      SSH_DEBUG(3, ("Could not init isakmp sa"));
      goto error;
    }
  ssh_free(auc);
  ssh_free(buc);
  ssh_free(cuc);
  ssh_free(duc);
  auc = NULL;
  buc = NULL;
  cuc = NULL;
  duc = NULL;

  neg = sa->isakmp_negotiation;
  pm_info = neg->ike_pm_info;

  /* Initialize */
  sa->phase_1_done = 1;
  neg->notification_state = SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
  ike_free_negotiation_isakmp(neg);


  /* Set NAT-T status. */
  local_port = ssh_uatoi(sa->isakmp_negotiation->ike_pm_info->local_port);
  if (local_port != server->normal_local_port)
    sa->use_natt = 1;

  /* I think we should count this as SA */
  server->statistics->current_ike_sas++;
  server->statistics->total_ike_sas++;
  if (neg->ike_pm_info->this_end_is_initiator)
    {
      server->statistics->current_ike_sas_initiated++;
      server->statistics->total_ike_sas_initiated++;
    }
  else
    {
      server->statistics->current_ike_sas_responded++;
      server->statistics->total_ike_sas_responded++;
    }

  len = ssh_decode_buffer
    (buffer,
     /* Byte count and byte limit. */
     SSH_DECODE_UINT64(&a64),
     SSH_DECODE_UINT64(&b64),
     /* Created time and laste use time */
     SSH_DECODE_UINT64(&c64),
     SSH_DECODE_UINT64(&d64),
     /* Encryption, hash, prf algorithm names. */
     SSH_DECODE_UINT32_STR(&auc, NULL),
     SSH_DECODE_UINT32_STR(&buc, NULL),
     SSH_DECODE_UINT32_STR(&cuc, NULL),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode byte count limit, times, alg names"));
      goto error;
    }
  sa->byte_count = (unsigned long) a64;
  sa->kbyte_limit = (unsigned long) b64;
  sa->created_time = (SshTime) c64;
  sa->last_use_time = (SshTime) d64;

  l = ssh_find_keyword_number(ssh_ike_encryption_algorithms, ssh_csstr(auc));
  if (l == -1)
    {
      if (ssh_usstrcmp(auc, "cast128-12-cbc") == 0)
        sa->encryption_algorithm_name = ssh_custr("cast128-12-cbc");
      else
        {
          SSH_DEBUG(3, ("Unknown cipher %s", auc));
          goto error;
        }
    }
  else
    {
      sa->encryption_algorithm_name =
        ssh_custr(ssh_find_keyword_name(ssh_ike_encryption_algorithms, l));
      SSH_ASSERT(sa->encryption_algorithm_name != NULL);
    }

  l = ssh_find_keyword_number(ssh_ike_hash_algorithms, ssh_csstr(buc));
  if (l == -1)
    {
      SSH_DEBUG(3, ("Unknown hash %s", buc));
      goto error;
    }
  else
    {
      sa->hash_algorithm_name =
        ssh_custr(ssh_find_keyword_name(ssh_ike_hash_algorithms, l));
      SSH_ASSERT(sa->hash_algorithm_name != NULL);
    }

  l = ssh_find_keyword_number(ssh_ike_hmac_prf_algorithms, ssh_csstr(cuc));
  if (l == -1)
    {
      SSH_DEBUG(3, ("Unknown prf %s", cuc));
      goto error;
    }
  else
    {
      sa->prf_algorithm_name =
        ssh_custr(ssh_find_keyword_name(ssh_ike_hmac_prf_algorithms, l));
      SSH_ASSERT(sa->prf_algorithm_name != NULL);
    }

  ssh_free(auc);
  ssh_free(buc);
  ssh_free(cuc);
  ssh_free(duc);
  auc = NULL;
  buc = NULL;
  cuc = NULL;
  duc = NULL;

  len = ssh_decode_buffer
    (buffer,
     /* Cipher key. */
     SSH_DECODE_UINT32_STR(&sa->cipher_key, &sa->cipher_key_len),
     /* Cipher IV. */
     SSH_DECODE_UINT32_STR(&sa->cipher_iv, &sa->cipher_iv_len),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode cipher key, iv"));
      goto error;
    }

  len = ssh_decode_buffer
    (buffer,
     /* Keying material, Diffie-Hellman. */
     SSH_DECODE_UINT32_STR(&sa->skeyid.dh, &sa->skeyid.dh_size),
     /* Keying material, SKEYID mac. */
     SSH_DECODE_UINT32_STR(&sa->skeyid.skeyid, &sa->skeyid.skeyid_size),
     /* Keying material, SKEYID_d mac. */
     SSH_DECODE_UINT32_STR(&sa->skeyid.skeyid_d, &sa->skeyid.skeyid_d_size),
     /* Keying material, SKEYID_a mac. */
     SSH_DECODE_UINT32_STR(&sa->skeyid.skeyid_a, &sa->skeyid.skeyid_a_size),
     /* Keying material, SKEYID_e mac. */
     SSH_DECODE_UINT32_STR(&sa->skeyid.skeyid_e, &sa->skeyid.skeyid_e_size),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode skeyid"));
      goto error;
    }
  sa->skeyid.initialized = TRUE;

  cret = ssh_mac_allocate(ssh_csstr(sa->prf_algorithm_name),
                          sa->skeyid.skeyid,
                          sa->skeyid.skeyid_size,
                          &sa->skeyid.skeyid_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ssh_mac_allocate failed: %.200s",
                    ssh_crypto_status_message(cret)));
      goto error;
    }

  cret = ssh_mac_allocate(ssh_csstr(sa->prf_algorithm_name),
                          sa->skeyid.skeyid_a,
                          sa->skeyid.skeyid_a_size,
                          &sa->skeyid.skeyid_a_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ssh_mac_allocate failed: %.200s",
                    ssh_crypto_status_message(cret)));
      goto error;
    }
  cret = ssh_mac_allocate(ssh_csstr(sa->prf_algorithm_name),
                          sa->skeyid.skeyid_e,
                          sa->skeyid.skeyid_e_size,
                          &sa->skeyid.skeyid_e_mac);
  if (cret != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(3, ("ssh_mac_allocate failed: %.200s",
                    ssh_crypto_status_message(cret)));
      goto error;
    }

  len = ssh_decode_buffer
    (buffer,
     /* Retry defaults. */
     SSH_DECODE_UINT32(&sa->retry_limit),
     SSH_DECODE_UINT32(&sa->retry_timer),
     SSH_DECODE_UINT32(&sa->retry_timer_usec),
     SSH_DECODE_UINT32(&sa->retry_timer_max),
     SSH_DECODE_UINT32(&sa->retry_timer_max_usec),
     SSH_DECODE_UINT32(&sa->expire_timer),
     SSH_DECODE_UINT32(&sa->expire_timer_usec),
     /* Statistics. */
     SSH_DECODE_UINT32(&sa->statistics.packets_in),
     SSH_DECODE_UINT32(&sa->statistics.packets_out),
     SSH_DECODE_UINT32(&sa->statistics.octects_in),
     SSH_DECODE_UINT32(&sa->statistics.octects_out),
     SSH_DECODE_UINT32(&sa->statistics.created_suites),
     SSH_DECODE_UINT32(&sa->statistics.deleted_suites),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode retry, expire timers and stats"));
      goto error;
    }

  len = ssh_decode_buffer
    (buffer,
     /* IKE SA negotiation information. */
     SSH_DECODE_UINT32(&a32),
     SSH_DECODE_UINT32(&b32),





     SSH_DECODE_UINT32(&c32),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode ike sa info and private group cnt"));
      goto error;
    }
  neg->exchange_type = a32;
  /* The b32 used to be authe_method_type, but as it was duplicate for the
     value in pm_info, we ignore it now. */
  if (c32 != 0)
    {
      ssh_warning("Remote end sent packet including private groups. "
                  "This end does not support transferring of them. "
                  "Private groups ignored");
    }
  len = ssh_decode_buffer
    (buffer,
     /* Private groups as UINT32_STRING. */



     SSH_DECODE_UINT32_STR(NULL, NULL),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode private groups info"));
      goto error;
    }

  if (!ssh_ike_sa_import_id(buffer, &pm_info->local_id,
                            &pm_info->local_id_txt))
    {
      SSH_DEBUG(3, ("Could not decode local id"));
      goto error;
    }
  if (!ssh_ike_sa_import_id(buffer, &pm_info->remote_id,
                            &pm_info->remote_id_txt))
    {
      SSH_DEBUG(3, ("Could not decode remote id"));
      goto error;
    }

  len = ssh_decode_buffer
    (buffer,
     /* Authentication type. */
     SSH_DECODE_UINT32(&a32),
     SSH_DECODE_UINT32(&b32),
     /* Start and expire times. */
     SSH_DECODE_UINT64(&a64),
     SSH_DECODE_UINT64(&b64),
     /* None of the policy manager filled data is copied, this include
        auth_data, auth_data_len, own_auth_data, own_auth_data_len,
        public_key, number_of_certificates, number_of_allocated_certificates,
        certificates, certificate_lens, certificate_encodings,
        policy_manager_data, pm. */
     SSH_DECODE_UINT32(&c32),
     /* Magic number */
     SSH_DECODE_UINT32(&d32),
     SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(3, ("Could not decode pm info and magic2"));
      goto error;
    }
  pm_info->auth_method_type = a32;
  pm_info->auth_method = b32;
  pm_info->sa_start_time = (SshTime) a64;
  pm_info->sa_expire_time = (SshTime) b64;
  pm_info->doi = c32;
  if (d32 != SSH_IKE_EXPORT_MAGIC2)
    {
      SSH_DEBUG(3, ("Invalid magic2 0x%08x vs 0x%08x", (int) d32,
                    SSH_IKE_EXPORT_MAGIC2));
      goto error;
    }

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, neg);
  /* Insert expire timer allowing the sa to exists for a while (for
     bootstrap) */
  t = ssh_time();
  if (t < pm_info->sa_expire_time)
    t = pm_info->sa_expire_time - t;
  else
    t = 0;

  t = (t < 30) ? 30 : t;
  ssh_xregister_timeout((SshUInt32) t, 0,
                       ike_call_ike_remove_isakmp_sa,
                       neg);
  return neg;
 error:
  if (sa != NULL)
    {
      if (sa->isakmp_negotiation == NULL)
        {
          ike_sa_delete(server->isakmp_context, sa);
          ssh_free(sa);
        }
      else
        ike_delete_negotiation(sa->isakmp_negotiation);
    }
  ssh_free(auc);
  ssh_free(buc);
  ssh_free(cuc);
  ssh_free(duc);
  return NULL;
}






