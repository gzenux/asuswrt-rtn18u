/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linearizing IKE and IPsec SAs and the reverse - installing them back.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "quicksecpm_internal.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshPmLinearize"


#ifdef SSHDIST_IPSEC_SA_EXPORT

/************************** Types and definitions ***************************/

/** Encoding format version:
    Ver 1: Original format after rewrite.
    Ver 2: Tunnel, outer tunnel and rule application identifiers and transform
           interface name were added, transform data encoding was fixed.
*/

#define SSH_PM_SA_EXPORT_VERSION             0x00000002

/** Type of encoded buffer. */
#define SSH_PM_SA_EXPORT_IKE_SA              0x00000001
#define SSH_PM_SA_EXPORT_IPSEC_SA            0x00000002
#define SSH_PM_SA_EXPORT_IKE_SA_DESTROYED    0x00000004
#define SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED  0x00000008


/***************************** Rendering SPI values **************************/
#ifdef DEBUG_LIGHT
static int pm_ipsec_spi_render(unsigned char *buf, int buf_size,
                               int precision, void *datum)
{
  SshPmQm qm = datum;
  SshEngineTransformData trd;
  int len;

  if (qm == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
    }
  else
    {
      SSH_PM_ASSERT_QM(qm);
      trd = &qm->sa_handler_data.trd.data;

      if (qm->transform & SSH_PM_IPSEC_ESP)
        len = ssh_snprintf(buf, buf_size + 1,
                           "ESP-%08lx", trd->spis[SSH_PME_SPI_ESP_IN]);
      else if (qm->transform & SSH_PM_IPSEC_AH)
        len = ssh_snprintf(buf, buf_size + 1,
                           "AH-%08lx", trd->spis[SSH_PME_SPI_AH_IN]);
      else
        len = ssh_snprintf(buf, buf_size + 1, "unknown-protocol-0");
    }

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

static int pm_ike_spi_render(unsigned char *buf, int buf_size,
                             int precision, void *datum)
{
  unsigned char *ike_spi = datum;
  int len;

  if (ike_spi == NULL)
    len = ssh_snprintf(buf, buf_size + 1, "(null)");
  else
    len = ssh_snprintf(buf, buf_size + 1, "%02x%02x%02x%02x %02x%02x%02x%02x",
                       ike_spi[0], ike_spi[1], ike_spi[2], ike_spi[3],
                       ike_spi[4], ike_spi[5], ike_spi[6], ike_spi[7]);

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}
#endif /* DEBUG_LIGHT */
/***************************** Encoding Identities ***************************/

static unsigned char *
pm_util_encode_id(SshIkev2PayloadID id, size_t *id_len_ret)
{
  unsigned char *id_ret;
  size_t len;

  if (id == NULL)
    {
      *id_len_ret = 0;
      return NULL;
    }

  switch (id->id_type)
    {
    case SSH_IKEV2_ID_TYPE_IPV4_ADDR:
      len = 4;
      break;
    case SSH_IKEV2_ID_TYPE_IPV6_ADDR:
      len = 16;
      break;
    default:
      len = id->id_data_size;
      break;
    }

  *id_len_ret =
    ssh_encode_array_alloc(&id_ret,
                           SSH_ENCODE_CHAR((unsigned int) id->id_type),
                           SSH_ENCODE_UINT32_STR(id->id_data, len),
                           SSH_FORMAT_END);

  return id_ret;
}

static SshIkev2PayloadID
pm_util_decode_id(unsigned char *data, size_t data_len)
{
  SshIkev2PayloadID id;
  size_t len;

  if (data_len == 0)
    return NULL;

  id = ssh_calloc(1, sizeof(*id));
  if (id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate memory for identity data"));
      return NULL;
    }

  len =
    ssh_decode_array(data, data_len,
                     SSH_DECODE_CHAR((unsigned int *)&id->id_type),
                     SSH_DECODE_UINT32_STR(&id->id_data, &id->id_data_size),
                     SSH_FORMAT_END);

  if (len != data_len)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Encoded identity %@ has %d bytes trailing garbage",
                 ssh_pm_ike_id_render, id, data_len - len));
      ssh_free(id);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Decoded ID %@", ssh_pm_ike_id_render, id));
  return id;
}


/***************************** Encoding Traffic Selectors ********************/

static unsigned char *
pm_util_encode_ts(SshIkev2PayloadTS ts, size_t *encoded_ts_len_ret)
{
  unsigned char *encoded_ts = NULL;
  SshBufferStruct buffer[1];
  int i;
  size_t encoded_length;

  ssh_buffer_init(buffer);

  encoded_length =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32(ts->number_of_items_used),
                      SSH_FORMAT_END);
  if (encoded_length == 0)
    goto error;

  for (i = 0; i < ts->number_of_items_used; i++)
    {
      encoded_length =
        ssh_encode_buffer(buffer,
                          SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                             ts->items[i].start_address),
                          SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                             ts->items[i].end_address),
                          SSH_ENCODE_CHAR(ts->items[i].proto),
                          SSH_ENCODE_UINT16(ts->items[i].start_port),
                          SSH_ENCODE_UINT16(ts->items[i].end_port),
                          SSH_FORMAT_END);
      if (encoded_length == 0)
        goto error;
    }

  encoded_ts = ssh_buffer_steal(buffer, encoded_ts_len_ret);
  ssh_buffer_uninit(buffer);
  return encoded_ts;

 error:
  *encoded_ts_len_ret = 0;
  ssh_buffer_uninit(buffer);
  return NULL;
}

static SshIkev2PayloadTS
pm_util_decode_ts(SshPm pm, unsigned char *data, size_t data_len)
{
  SshIpAddrStruct start[1], end[1];
  SshUInt16 sport, eport;
  SshIkev2PayloadTS ts;
  size_t offset;
  int i;
  unsigned int proto;
  SshUInt32 nitems;

  offset = ssh_decode_array(data, data_len,
                            SSH_DECODE_UINT32(&nitems),
                            SSH_FORMAT_END);

  if (offset != 4 || nitems == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Traffic selector decode failed"));
      return NULL;
    }

  ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (ts == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate a traffic selector"));
      return NULL;
    }

  for (i = 0; i < nitems; i++)
    {
      offset +=
        ssh_decode_array(data + offset, data_len - offset,
                         SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                    start),
                         SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                    end),
                         SSH_DECODE_CHAR(&proto),
                         SSH_DECODE_UINT16(&sport),
                         SSH_DECODE_UINT16(&eport),
                         SSH_FORMAT_END);

      if (ssh_ikev2_ts_item_add(ts, proto, start, end, sport, eport)
          != SSH_IKEV2_ERROR_OK)
        goto error;
    }

  if (offset != data_len)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Encoded traffic selector %@ has %d bytes trailing garbage",
                 ssh_ikev2_ts_render, ts, data_len - offset));
      goto error;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Decoded TS %@", ssh_ikev2_ts_render, ts));
  return ts;

 error:
  ssh_ikev2_ts_free(pm->sad_handle, ts);
  return NULL;
}


/***************************** Encoding remote access attributes *************/

#ifdef SSHDIST_ISAKMP_CFG_MODE
static unsigned char *
pm_util_encode_ras_attrs(SshPmRemoteAccessAttrs ras_attrs,
                         size_t *encoded_ras_attrs_len)
{
  SshBufferStruct buffer[1];
  SshUInt32 i;
  size_t len;
  unsigned char *encoded_ras_attrs = NULL;

  SSH_ASSERT(encoded_ras_attrs_len != NULL);

  if (ras_attrs == NULL)
    {
      *encoded_ras_attrs_len = 0;
      return NULL;
    }

  ssh_buffer_init(buffer);

  /* Encode RAS addresses. */
  if (ras_attrs->address_expiry_set)
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(ras_attrs->address_expiry),
                            SSH_FORMAT_END);
  else
    len = ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32(0),
                            SSH_FORMAT_END);
  if (len != 4)
    goto error;

  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(ras_attrs->num_addresses),
                          SSH_FORMAT_END);
  if (len != 4)
    goto error;

  for (i = 0; i < ras_attrs->num_addresses; i++)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                 &ras_attrs->addresses[i]),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }

  /* Encode DHCP server DUID */
  if (ras_attrs->server_duid_len > 0)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_UINT16(ras_attrs->server_duid_len),
                              SSH_FORMAT_END);
      if (len != 2)
        goto error;

      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_DATA(ras_attrs->server_duid,
                                              ras_attrs->server_duid_len),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }
  else
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_UINT16((SshUInt16)0),
                              SSH_FORMAT_END);
      if (len != 2)
        goto error;
    }

  /* Encode DNS addresses. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(ras_attrs->num_dns),
                          SSH_FORMAT_END);
  if (len != 4)
    goto error;

  for (i = 0; i < ras_attrs->num_dns; i++)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                 &ras_attrs->dns[i]),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }

  /* Encode WINS addresses. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(ras_attrs->num_wins),
                          SSH_FORMAT_END);
  if (len != 4)
    goto error;

  for (i = 0; i < ras_attrs->num_wins; i++)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                 &ras_attrs->wins[i]),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }

  /* Encode DHCP addresses. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(ras_attrs->num_dhcp),
                          SSH_FORMAT_END);
  if (len != 4)
    goto error;

  for (i = 0; i < ras_attrs->num_dhcp; i++)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                 &ras_attrs->dhcp[i]),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }

  /* Encode subnets. */
  len =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32(ras_attrs->num_subnets),
                      SSH_FORMAT_END);
  if (len != 4)
    goto error;

  for (i = 0; i < ras_attrs->num_subnets; i++)
    {
      len = ssh_encode_buffer(buffer,
                              SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                                 &ras_attrs->subnets[i]),
                              SSH_FORMAT_END);
      if (len == 0)
        goto error;
    }

  encoded_ras_attrs = ssh_buffer_steal(buffer, encoded_ras_attrs_len);
  ssh_buffer_uninit(buffer);
  return encoded_ras_attrs;

 error:
  *encoded_ras_attrs_len = 0;
  return NULL;
}


static Boolean
pm_util_decode_p1_ras_attrs(const unsigned char *buf,
                            size_t buf_len,
                            SshPmRemoteAccessAttrs ras_attrs)
{
  size_t len, offset;
  SshUInt32 i;
  SshUInt32 num_addresses;

  SSH_ASSERT(ras_attrs != NULL);

  /* Decode RAS addresses. */
  len =
    ssh_decode_array(buf, buf_len,
                     SSH_DECODE_UINT32(&ras_attrs->address_expiry),
                     SSH_DECODE_UINT32(&num_addresses),
                     SSH_FORMAT_END);
  if (len != 8 || (num_addresses > SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES))
    goto error;
  offset = len;

  if (ras_attrs->address_expiry > 0)
    ras_attrs->address_expiry_set = TRUE;

  ras_attrs->num_addresses = num_addresses;

  for (i = 0; i < ras_attrs->num_addresses; i++)
    {
      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_SPECIAL_NOALLOC(
                             ssh_decode_ipaddr_array,
                             &ras_attrs->addresses[i]),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }

  /* Decode DHCP server DUID */
  len =
    ssh_decode_array(buf +  offset, buf_len - offset,
                     SSH_DECODE_UINT16(&ras_attrs->server_duid_len),
                     SSH_FORMAT_END);
  offset += len;

  if (ras_attrs->server_duid_len > 0)
    {
      ras_attrs->server_duid = ssh_calloc(1, ras_attrs->server_duid_len);
      if (ras_attrs->server_duid == NULL)
        goto error;

      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_DATA(ras_attrs->server_duid,
                                          (size_t)ras_attrs->server_duid_len),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }
  else
    {
      ras_attrs->server_duid = NULL;
    }

  /* Decode DNS addresses. */
  len = ssh_decode_array(buf + offset, buf_len - offset,
                         SSH_DECODE_UINT32(&ras_attrs->num_dns),
                         SSH_FORMAT_END);
  if (len != 4
      || (ras_attrs->num_dns > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
    goto error;
  offset += len;

  for (i = 0; i < ras_attrs->num_dns; i++)
    {
      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_SPECIAL_NOALLOC(
                             ssh_decode_ipaddr_array,
                             &ras_attrs->dns[i]),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }

  /* Decode WINS addresses. */
  len = ssh_decode_array(buf + offset, buf_len - offset,
                         SSH_DECODE_UINT32(&ras_attrs->num_wins),
                         SSH_FORMAT_END);
  if (len != 4
      || (ras_attrs->num_wins > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
    goto error;
  offset += len;

  for (i = 0; i < ras_attrs->num_wins; i++)
    {
      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_SPECIAL_NOALLOC(
                             ssh_decode_ipaddr_array,
                             &ras_attrs->wins[i]),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }

  /* Decode DHCP addresses. */
  len = ssh_decode_array(buf + offset, buf_len - offset,
                         SSH_DECODE_UINT32(&ras_attrs->num_dhcp),
                         SSH_FORMAT_END);
  if (len != 4
      || (ras_attrs->num_dhcp > SSH_PM_REMOTE_ACCESS_NUM_SERVERS))
    goto error;
  offset += len;

  for (i = 0; i < ras_attrs->num_dhcp; i++)
    {
      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_SPECIAL_NOALLOC(
                             ssh_decode_ipaddr_array,
                             &ras_attrs->dhcp[i]),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }

  /* Decode subnets. */
  len = ssh_decode_array(buf + offset, buf_len - offset,
                         SSH_DECODE_UINT32(&ras_attrs->num_subnets),
                         SSH_FORMAT_END);
  if (len != 4
      || (ras_attrs->num_subnets > SSH_PM_REMOTE_ACCESS_NUM_SUBNETS))
    goto error;
  offset += len;

  for (i = 0; i < ras_attrs->num_subnets; i++)
    {
      len = ssh_decode_array(buf + offset, buf_len - offset,
                             SSH_DECODE_SPECIAL_NOALLOC(
                             ssh_decode_ipaddr_array,
                             &ras_attrs->subnets[i]),
                             SSH_FORMAT_END);
      if (len == 0)
        goto error;

      offset += len;
    }

  /* Check that decoding consumed all data. */
  if (offset != buf_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Encoded RAS attribute has %d trailing garbage",
                             buf_len - offset));
      goto error;
    }

  return TRUE;

 error:
  if (ras_attrs->server_duid != NULL)
    ssh_free(ras_attrs->server_duid);
  ras_attrs->server_duid = NULL;
  ras_attrs->server_duid_len = 0;

  SSH_DEBUG(SSH_D_FAIL, ("RAS attribute decode failed"));
  return FALSE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/***************************** Public functions *****************************/

/* Perform housekeeping tasks after all IKE and IPSec SAs have been
   imported. */
void
ssh_pm_import_finalize(SshPm pm)
{
  /* Reevaluate all flows. Importing IPsec SAs sets the 'own_ifnum' to the
     SshTransformData structure in the engine.  */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_ACTIVE)
  ssh_pm_redo_flows(pm);

  SSH_APE_MARK(1, ("SA import done"));
}


/***************************** IKE SA export *********************************/


static size_t
pm_ike_sa_encode_deleted_event(SshPm pm,
                               SshPmIkeSAEventHandle ike_sa,
                               SshBuffer buffer)
{
  size_t total_len;
  SshUInt32 ike_version = 2;

#ifdef SSHDIST_IKEV1
  if (ike_sa->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    ike_version = 1;
#endif /* SSHDIST_IKEV1 */

  /* Encode fixed IPsec SA export header, IP protocol and SPI values. */
  total_len =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                      SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IKE_SA_DESTROYED),
                      SSH_ENCODE_UINT32(ike_version),
                      SSH_ENCODE_DATA(ike_sa->p1->ike_sa->ike_spi_i,
                                      (size_t) 8),
                      SSH_ENCODE_DATA(ike_sa->p1->ike_sa->ike_spi_r,
                                      (size_t) 8),
                      SSH_FORMAT_END);
  if (total_len == 0)
    goto encode_error;

  SSH_DEBUG(SSH_D_LOWOK, ("IKEv%d SA %@ destroyed event encoded",
                          ike_version,
                          ssh_ikev2_ike_spi_render, ike_sa->p1->ike_sa));

  return total_len;

 encode_error:
  SSH_DEBUG(SSH_D_FAIL, ("IKEv%d SA %@ destroyed event encode failed",
                         ike_version,
                         ssh_ikev2_ike_spi_render, ike_sa->p1->ike_sa));
  return 0;
}


/* Flag values for IKE SA import_flags. */
#define SSH_PM_IKE_SA_IMPORT_FLAG_RAS                    0x0001
#define SSH_PM_IKE_SA_IMPORT_FLAG_RAC                    0x0002
#define SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED                0x0004
#define SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET     0x0008
#define SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK 0x0010

size_t
ssh_pm_ike_sa_export(SshPm pm, SshPmIkeSAEventHandle ike_sa, SshBuffer buffer)
{
  SshPmP1 p1;
  unsigned char *encoded_ike_sa = NULL;
  size_t encoded_ike_sa_len = 0;
  unsigned char *local_id = NULL;
  size_t local_id_len = 0;
  unsigned char *remote_id = NULL;
  size_t remote_id_len = 0;
  unsigned char *second_local_id = NULL;
  size_t second_local_id_len = 0;
  unsigned char *second_remote_id = NULL;
  size_t second_remote_id_len = 0;
  SshPmAuthMethod second_local_auth_method = SSH_PM_AUTH_NONE;
  SshPmAuthMethod second_remote_auth_method = SSH_PM_AUTH_NONE;
  unsigned char *eap_remote_id = NULL;
  size_t eap_remote_id_len = 0;
  unsigned char *second_eap_remote_id = NULL;
  size_t second_eap_remote_id_len = 0;
  unsigned char *ras_attrs = NULL;
  size_t ras_attrs_len = 0;
  size_t len, total_len = 0;
  SshUInt32 i;
  SshUInt16 local_port;
  SshUInt32 import_flags = 0;
  SshPmTunnel tunnel;
  unsigned char *tunnel_app_id;
  size_t tunnel_app_id_len = 0;

  /* Check input parameters. */
  if (ike_sa == NULL || buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      return 0;
    }

  if (ike_sa->event == SSH_PM_SA_EVENT_DELETED)
    return pm_ike_sa_encode_deleted_event(pm, ike_sa, buffer);

  p1 = ike_sa->p1;

  /* Do not export failed, not-yet-done and unusable IKE SAs, except
     allow export of rekeyed IKE SA (which is always unusable when
     exported). */
  if (p1->failed || !p1->done || (p1->unusable && !p1->rekeyed))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot export unusable IKE SA"));
      return 0;
    }

  if (p1->rekeyed)
    import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED;

  if (p1->auth_group_ids_set)
    import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET;

  /* Encode identities. */
  remote_id = pm_util_encode_id(p1->remote_id, &remote_id_len);
  if (p1->remote_id && remote_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE remote identity encode failed"));
      goto error;
    }
  local_id = pm_util_encode_id(p1->local_id, &local_id_len);
  if (p1->local_id && local_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE local identity encode failed"));
      goto error;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  second_remote_id = pm_util_encode_id(p1->second_remote_id,
                                       &second_remote_id_len);
  if (p1->second_remote_id && second_remote_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE second remote identity encode failed"));
      goto error;
    }
  second_local_id = pm_util_encode_id(p1->second_local_id,
                                      &second_local_id_len);
  if (p1->second_local_id && second_local_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE second local identity encode failed"));
      goto error;
    }
  second_local_auth_method = p1->second_local_auth_method;
  second_remote_auth_method = p1->second_remote_auth_method;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
  eap_remote_id = pm_util_encode_id(p1->eap_remote_id, &eap_remote_id_len);
  if (p1->eap_remote_id && eap_remote_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE EAP remote identity encode failed"));
      goto error;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  second_eap_remote_id = pm_util_encode_id(p1->second_eap_remote_id,
                                           &second_eap_remote_id_len);
  if (p1->second_eap_remote_id && second_eap_remote_id == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE second EAP remote identity encode failed"));
      goto error;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
  if (p1->enable_blacklist_check)
    import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Encode RAS attributes. */
  if (p1->remote_access_attrs)
    {
      ras_attrs = pm_util_encode_ras_attrs(p1->remote_access_attrs,
                                           &ras_attrs_len);
      if (ras_attrs == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE RAS attribute encode failed"));
          goto error;
        }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      if (p1->cfgmode_client)
        import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_RAS;
      else
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
        import_flags |= SSH_PM_IKE_SA_IMPORT_FLAG_RAC;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  tunnel = ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA tunnel_id %d",
                             (int) p1->tunnel_id));
      goto error;
    }
  tunnel_app_id = tunnel->application_identifier;
  tunnel_app_id_len = tunnel->application_identifier_len;

  /* Encode the ikev2 library part of IKE SA. */
  if (ssh_ikev2_encode_sa(p1->ike_sa, &encoded_ike_sa, &encoded_ike_sa_len)
      != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }

  /* Encode fixed IKE SA export header to export buffer. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                          SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IKE_SA),
                          SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA export header encode failed"));
      goto error;
    }
  total_len = len;

  /* Encode p1 body to export buffer. */
  local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                             p1->ike_sa->remote_ip),
                          SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                             &p1->ike_sa->server->ip_address),
                          SSH_ENCODE_UINT16(local_port),
                          SSH_ENCODE_UINT64(p1->expire_time),
                          SSH_ENCODE_UINT64(p1->lifetime),
                          SSH_ENCODE_UINT16(p1->dh_group),
                          SSH_ENCODE_UINT16(p1->local_auth_method),
                          SSH_ENCODE_UINT16(p1->remote_auth_method),
                          SSH_ENCODE_UINT32_STR(local_id, local_id_len),
                          SSH_ENCODE_UINT32_STR(remote_id, remote_id_len),
                          SSH_ENCODE_UINT16(second_local_auth_method),
                          SSH_ENCODE_UINT16(second_remote_auth_method),
                          SSH_ENCODE_UINT32_STR(second_local_id,
                                                second_local_id_len),
                          SSH_ENCODE_UINT32_STR(second_remote_id,
                                                second_remote_id_len),
                          SSH_ENCODE_UINT32_STR(eap_remote_id,
                                                eap_remote_id_len),
                          SSH_ENCODE_UINT32_STR(second_eap_remote_id,
                                                second_eap_remote_id_len),
                          SSH_ENCODE_UINT32_STR(p1->local_secret,
                                                p1->local_secret_len),
                          SSH_ENCODE_UINT32(p1->compat_flags),
                          SSH_ENCODE_UINT32(p1->tunnel_id),
                          SSH_ENCODE_UINT32_STR(p1->old_ike_spi_i, 8),
                          SSH_ENCODE_UINT32_STR(p1->old_ike_spi_r, 8),
                          SSH_ENCODE_UINT32(import_flags),
                          SSH_ENCODE_UINT32_STR(tunnel_app_id,
                                                tunnel_app_id_len),
                          SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }
  total_len += len;

  /* Encode authorization group ids to export buffer. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(p1->num_authorization_group_ids),
                          SSH_FORMAT_END);
  if (len != 4)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }
  total_len += len;

  for (i = 0; i < p1->num_authorization_group_ids; i++)
    {
      SSH_ASSERT(p1->auth_group_ids_set);

      len =
        ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(p1->authorization_group_ids[i]),
                          SSH_FORMAT_END);
      if (len != 4)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
          goto error;
        }
      total_len += len;
    }

  /* Encode XAUTH authorization group ids to export buffer. */
  len =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32(p1->num_xauth_authorization_group_ids),
                      SSH_FORMAT_END);
  if (len != 4)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }
  total_len += len;

  for (i = 0; i < p1->num_xauth_authorization_group_ids; i++)
    {
      len = ssh_encode_buffer(buffer,
                       SSH_ENCODE_UINT32(p1->xauth_authorization_group_ids[i]),
                       SSH_FORMAT_END);
      if (len != 4)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
          goto error;
        }
      total_len += len;
    }

  /* Encode remote access attributes to export buffer. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32_STR(ras_attrs, ras_attrs_len),
                          SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }
  total_len += len;

  /* Append the encoded IKE SA to export buffer. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32_STR(encoded_ike_sa,
                                                encoded_ike_sa_len),
                          SSH_FORMAT_END);
  if (len == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA encode failed"));
      goto error;
    }
  total_len += len;

  ssh_free(local_id);
  ssh_free(remote_id);
  ssh_free(second_local_id);
  ssh_free(second_remote_id);
  ssh_free(eap_remote_id);
  ssh_free(second_eap_remote_id);
  ssh_free(ras_attrs);
  ssh_free(encoded_ike_sa);

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %@ - %@ exported, len %d",
                          pm_ike_spi_render, p1->ike_sa->ike_spi_i,
                          pm_ike_spi_render, p1->ike_sa->ike_spi_r,
                          total_len));

  return total_len;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Could not export IKE SA %@ - %@",
                         pm_ike_spi_render, p1->ike_sa->ike_spi_i,
                         pm_ike_spi_render, p1->ike_sa->ike_spi_r));

  ssh_free(local_id);
  ssh_free(remote_id);
  ssh_free(second_local_id);
  ssh_free(second_remote_id);
  ssh_free(eap_remote_id);
  ssh_free(second_eap_remote_id);
  ssh_free(ras_attrs);
  ssh_free(encoded_ike_sa);

  /* Remove any already encoded data from buffer. */
  ssh_buffer_consume_end(buffer, total_len);

  return 0;
}

/***************************** IKE SA import *********************************/

/* Context data for IKE SA installation */
struct SshPmImportIkeInstallRec
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /* Keep this element first, RAS state machine relies on it. */
  SshPmIkev2ConfQueryStruct query[1];
  SshIkev2ExchangeDataStruct ed;
  SshIkev2SaExchangeDataStruct ike_ed;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  SshPmRemoteAccessAttrsStruct remote_access_attrs[1];
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  SshBuffer buffer;
  SshPmSAImportStatus error;
  SshPm pm;
  SshPmP1 p1;
  SshIpAddrStruct remote_ip[1];
  SshIpAddrStruct server_ip[1];
  SshUInt16 server_local_port;

  unsigned char *encoded_ike_sa;
  size_t encoded_ike_sa_len;
  Boolean ike_sa_decoded;

  SshUInt32 import_flags;
  unsigned char *tunnel_app_id;
  size_t tunnel_app_id_len;

  SshFSMThreadStruct thread;

  SshPmIkeSAPreImportCB import_cb;
  void *import_context;
  SshPmIkeSAImportStatusCB status_cb;
  void *status_context;
};

typedef struct SshPmImportIkeInstallRec *SshPmImportIkeInstall;

/* FSM state declarations */
SSH_FSM_STEP(pm_st_ike_sa_import_start);
SSH_FSM_STEP(pm_st_ike_sa_import_install);
SSH_FSM_STEP(pm_st_ike_sa_import_failed);
SSH_FSM_STEP(pm_st_ike_sa_import_terminate);
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
SSH_FSM_STEP(pm_st_ike_sa_import_ras_alloc);
SSH_FSM_STEP(pm_st_ike_sa_import_ras_done);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Callback function for pre import hook */
static void
pm_ike_sa_import_hook_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmImportIkeInstall install =
    (SshPmImportIkeInstall) ssh_fsm_get_tdata(thread);

  if (!success)
    {
      install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      ssh_fsm_set_next(thread, pm_st_ike_sa_import_failed);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Call import hook function */
SSH_FSM_STEP(pm_st_ike_sa_import_start)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_install);

  if (install->import_cb)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Calling IKE SA import hook"));

      ike_sa.event = SSH_PM_SA_EVENT_CREATED;
      ike_sa.p1 = install->p1;
      ike_sa.tunnel_application_identifier = install->tunnel_app_id;
      ike_sa.tunnel_application_identifier_len = install->tunnel_app_id_len;

      SSH_FSM_ASYNC_CALL({
        (*install->import_cb)(install->pm,
                              &ike_sa,
                              install->remote_ip,
                              pm_ike_sa_import_hook_cb,
                              thread,
                              install->import_context);
      });

      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

/* Install IKE SA */
SSH_FSM_STEP(pm_st_ike_sa_import_install)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshPm pm = install->pm;
  SshPmP1 p1 = install->p1;
  SshPmTunnel tunnel;

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import install"));

  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);

  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA import failed, no tunnel found"));
      install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      goto error;
    }

  p1->ike_sa->server = ssh_pm_servers_select_ike(pm, install->server_ip,
                                      SSH_PM_SERVERS_MATCH_PORT,
                                      SSH_INVALID_IFNUM,
                                      install->server_local_port,
                                      tunnel->routing_instance_id);

  if (p1->ike_sa->server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA import failed, no IKE server available"));
      install->error = SSH_PM_SA_IMPORT_ERROR_NO_SERVER_FOUND;
      goto error;
    }

  /* Now that p1->ike_sa->server is set, decode ikev2 library part of IKE SA */
  if (ssh_ikev2_decode_sa(p1->ike_sa,
                          install->encoded_ike_sa, install->encoded_ike_sa_len)
      != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
      install->error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
      goto error;
    }
  install->ike_sa_decoded = TRUE;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (install->remote_access_attrs->num_addresses)
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      /* Reallocate RAS attributes if imported IKE SA has them
         and we are the server for this cfgmode IKE SA. */
      if ((install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAS)
          && (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED) == 0)
        {
          SSH_FSM_SET_NEXT(pm_st_ike_sa_import_ras_alloc);
          return SSH_FSM_CONTINUE;
        }
      else
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

      if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAC)
        {
          /* For clients just copy the remote access attributes to the p1. */
          p1->remote_access_attrs =
            ssh_pm_dup_remote_access_attrs(install->remote_access_attrs);
          if (p1->remote_access_attrs == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("IKE SA RAS attribute copy failed"));
              install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
              goto error;
            }
        }
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  return SSH_FSM_CONTINUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("IKE SA import install failed"));
  SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);
  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
SSH_FSM_STEP(pm_st_ike_sa_import_ras_alloc)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshPm pm = install->pm;

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import RAS allocation"));

  /* Fetch tunnel by `tunnel_id'. */
  install->query->tunnel = ssh_pm_tunnel_get_by_id(pm, install->p1->tunnel_id);
  if (install->query->tunnel == NULL)
    {
      install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      goto error;
    }
  SSH_PM_TUNNEL_TAKE_REF(install->query->tunnel);
  install->query->client_attributes = install->remote_access_attrs;

  /* Initialize rest of RAS query context */
  install->query->p1 = install->p1;
  install->query->error = SSH_IKEV2_ERROR_OK;
  install->query->conf_payload = NULL;
  install->query->index = 0;
  install->query->ike_sa_import = TRUE;
  install->query->fsm_st_done = pm_st_ike_sa_import_ras_done;

  /* Create a fake ike_ed and fill in identities from p1. */
  install->query->ed = &install->ed;
  install->query->ed->ike_sa = install->p1->ike_sa;
  install->query->ed->ref_cnt = 1;
  install->query->ed->ike_ed = &install->ike_ed;
  if (install->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      install->query->ed->ike_ed->id_i = install->p1->local_id;
      install->query->ed->ike_ed->id_r = install->p1->remote_id;
    }
  else
    {
      install->query->ed->ike_ed->id_i = install->p1->remote_id;
      install->query->ed->ike_ed->id_r = install->p1->local_id;
    }

  /* Finally record that we have such SA. */
  ssh_adt_insert(install->pm->sad_handle->ike_sa_by_spi, install->p1);
  ssh_pm_ike_sa_hash_insert(install->pm, install->p1);

  SSH_FSM_SET_NEXT(pm_ras_attrs_alloc);
  return SSH_FSM_CONTINUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("IKE SA import RAS allocation failed"));
  SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);
  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_ike_sa_import_ras_done)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshUInt32 i;

  /* Verify that the allocated RAS attributes match the requested.
     Delete IKE SA if they dont match. */
  if (install->p1->remote_access_attrs == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("RAS attribute allocation failed"));
      install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  else
    {
      for (i = 0; i < install->p1->remote_access_attrs->num_addresses; i++)
        {
          if (!SSH_IP_EQUAL(&install->p1->remote_access_attrs->addresses[i],
                            &install->query->client_attributes->addresses[i]))
            break;
        }
      if (i != install->p1->remote_access_attrs->num_addresses ||
          i != install->query->client_attributes->num_addresses)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Allocated RAS attributes do not match requested "
                     "attributes"));
          install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
          goto error;
        }
    }

  if (install->query->tunnel)
    SSH_PM_TUNNEL_DESTROY(install->pm, install->query->tunnel);
  install->query->tunnel = NULL;

  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);
  return SSH_FSM_CONTINUE;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("IKE SA import RAS done failed"));
  SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

  if (install->query->tunnel)
    SSH_PM_TUNNEL_DESTROY(install->pm, install->query->tunnel);
  install->query->tunnel = NULL;

  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_failed);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */


SSH_FSM_STEP(pm_st_ike_sa_import_failed)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshPmP1 p1 = install->p1;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_FAIL,
            ("Failed to import IKE SA %@ - %@, deleting SA",
             pm_ike_spi_render, p1->ike_sa->ike_spi_i,
             pm_ike_spi_render, p1->ike_sa->ike_spi_r));

  SSH_FSM_SET_NEXT(pm_st_ike_sa_import_terminate);

  SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

  handle = ssh_adt_get_handle_to_equal(install->pm->sad_handle->ike_sa_by_spi,
                                       p1->ike_sa);
  if (handle != SSH_ADT_INVALID)
    ssh_adt_detach(install->pm->sad_handle->ike_sa_by_spi, handle);

  if (install->ike_sa_decoded)
    ssh_ikev2_ike_sa_uninit(p1->ike_sa);
  ssh_pm_p1_free(install->pm, p1);

  return SSH_FSM_CONTINUE;
}


/* Terminate state machine and call completion callback */
SSH_FSM_STEP(pm_st_ike_sa_import_terminate)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) thread_context;
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA import terminate state"));

  if (install->error != SSH_PM_SA_IMPORT_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to import IKE SA"));

      if (install->status_cb != NULL_FNPTR)
        (*install->status_cb)(install->pm,
                              install->error, NULL,
                              install->status_context);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("IKE SA %@ - %@ imported",
                 pm_ike_spi_render, install->p1->ike_sa->ike_spi_i,
                 pm_ike_spi_render, install->p1->ike_sa->ike_spi_r));

      /* Mark IKE SA completed. */
      install->p1->done = 1;

      /* Mark IKE SA unusable if it was a rekeyed IKE SA. */
      if (install->p1->rekeyed)
        install->p1->unusable = 1;

      /* Enable SA events for the IKE SA. */
      install->p1->enable_sa_events = 1;

      /* Finally record that we have such SA (if RAS it is already done). */
      if ((install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_RAS) == 0
          || (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED) != 0)
        {
          ssh_adt_insert(install->pm->sad_handle->ike_sa_by_spi, install->p1);
          ssh_pm_ike_sa_hash_insert(install->pm, install->p1);
        }

#ifdef SSH_IPSEC_SMALL
      /* Register timeout for rekeying the IKE SA. */
      SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(install->p1,
                                  install->p1->expire_time
                                  - ssh_pm_ike_sa_soft_grace_time(install->p1),
                                  ssh_time());
#endif /* SSH_IPSEC_SMALL */

      if (install->status_cb != NULL_FNPTR)
        {
          /* Pass the IKE SA handle to application so that the possibly
             changed SA data can be re-exported. */
          memset(&ike_sa, 0, sizeof(ike_sa));
          ike_sa.p1 = install->p1;
          ike_sa.event = SSH_PM_SA_EVENT_CREATED;

          (*install->status_cb)(install->pm,
                                SSH_PM_SA_IMPORT_OK, &ike_sa,
                                install->status_context);
        }
    }

  return SSH_FSM_FINISH;
}

/* Thread destructor */
static void
pm_ike_sa_import_destructor(SshFSM fsm, void *context)
{
  SshPmImportIkeInstall install = (SshPmImportIkeInstall) context;

  if (install->remote_access_attrs->server_duid != NULL)
      ssh_free(install->remote_access_attrs->server_duid);

  ssh_free(install->tunnel_app_id);
  ssh_free(install);
}

/* Import IKE SA */

SshOperationHandle
ssh_pm_ike_sa_import(SshPm pm, SshBuffer buffer,
                     SshPmIkeSAPreImportCB import_callback,
                     void *import_callback_context,
                     SshPmIkeSAImportStatusCB status_callback,
                     void *status_callback_context)
{
  SshPmImportIkeInstall install = NULL;
  SshPmP1 p1 = NULL;
  SshUInt32 version, type;
  SshUInt16 local_auth_method, remote_auth_method;
  SshUInt16 second_local_auth_method, second_remote_auth_method;
  unsigned char *local_id, *remote_id;
  size_t local_id_len, remote_id_len;
  unsigned char *second_local_id, *second_remote_id;
  size_t second_local_id_len, second_remote_id_len;
  unsigned char *eap_remote_id;
  size_t eap_remote_id_len;
  unsigned char *second_eap_remote_id;
  size_t second_eap_remote_id_len;
  unsigned char *ras_attrs;
  size_t ras_attrs_len;
  unsigned char *old_ike_spi_i, *old_ike_spi_r;
  size_t old_ike_spi_i_len, old_ike_spi_r_len;
  size_t len = 0, i, offset;
  SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
  unsigned char *tunnel_app_id;
  size_t tunnel_app_id_len;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered IKE SA import"));

  if (buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid input buffer"));
      error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
      goto error;
    }

  /* The SA import-export API is designed for local SA storage and recovery
     after crash or suspend. This means that SA import does not need to
     consider SA rekeys or updates because the SAs are always imported in to
     an freshly initialized system without conflicting SAs.

     Support for redundant fail-over GW type of scenario would require atleast
     the following changes:

     * Import of IKE SA rekeys: Instead of SA installation the new IKE SA
       needs to be installed using ssh_pm_ike_sa_rekey().

     * Import of IKE SA updates: IKEv2 library needs to be enhanced with a
       a public API for encoding/decoding of the window. The policy manager
       needs to be modified to update IKE SA addresses using
       ssh_pm_peer_p1_update_address().

     * Export of IKE SA updates/rekeys: Encoding/decoding of the UPDATED,
       REKEYED and DELETED SA events needs to be added.
  */

  /* Decode fixed IKE SA export header. */
  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_UINT32(&version),
                             SSH_DECODE_UINT32(&type),
                             SSH_FORMAT_END);
  if (offset == 0
      || version != SSH_PM_SA_EXPORT_VERSION
      || type != SSH_PM_SA_EXPORT_IKE_SA)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header"));
      error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
      goto error;
    }

  /* Allocate p1 object for imported IKE SA. */
  p1 = ssh_pm_p1_alloc(pm);
  if (p1 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate p1"));
      error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Allocate temporary context for import operation. */
  install = ssh_calloc(1, sizeof(*install));
  if (install == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate import context for IKE SA"));
      error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  install->pm = pm;
  install->p1 = p1;
  install->error = SSH_PM_SA_IMPORT_OK;
  install->import_cb = import_callback;
  install->import_context = import_callback_context;
  install->status_cb = status_callback;
  install->status_context = status_callback_context;
  install->buffer = buffer;

  /* Decode p1 body. */
  offset =
    ssh_decode_buffer(install->buffer,
                      SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                 install->remote_ip),
                      SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                 install->server_ip),
                      SSH_DECODE_UINT16(&install->server_local_port),
                      SSH_DECODE_UINT64(&p1->expire_time),
                      SSH_DECODE_UINT64(&p1->lifetime),
                      SSH_DECODE_UINT16(&p1->dh_group),
                      SSH_DECODE_UINT16(&local_auth_method),
                      SSH_DECODE_UINT16(&remote_auth_method),
                      SSH_DECODE_UINT32_STR_NOCOPY(&local_id, &local_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&remote_id, &remote_id_len),
                      SSH_DECODE_UINT16(&second_local_auth_method),
                      SSH_DECODE_UINT16(&second_remote_auth_method),
                      SSH_DECODE_UINT32_STR_NOCOPY(&second_local_id,
                                                   &second_local_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&second_remote_id,
                                                   &second_remote_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&eap_remote_id,
                                                   &eap_remote_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&second_eap_remote_id,
                                                   &second_eap_remote_id_len),
                      SSH_DECODE_UINT32_STR(&p1->local_secret,
                                            &p1->local_secret_len),
                      SSH_DECODE_UINT32(&p1->compat_flags),
                      SSH_DECODE_UINT32(&p1->tunnel_id),
                      SSH_DECODE_UINT32_STR_NOCOPY(&old_ike_spi_i,
                                                   &old_ike_spi_i_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&old_ike_spi_r,
                                                   &old_ike_spi_r_len),
                      SSH_DECODE_UINT32(&install->import_flags),
                      SSH_DECODE_UINT32_STR_NOCOPY(&tunnel_app_id,
                                                   &tunnel_app_id_len),
                      SSH_FORMAT_END);

  if (offset == 0)
    goto decode_error;

  if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_REKEYED)
    p1->rekeyed = 1;
  else
    p1->rekeyed = 0;

  if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_AUTH_GROUP_IDS_SET)
    p1->auth_group_ids_set = 1;
  else
    p1->auth_group_ids_set = 0;

  if (old_ike_spi_i_len != 8 || old_ike_spi_r_len != 8)
    goto decode_error;

  memcpy(p1->old_ike_spi_i, old_ike_spi_i, 8);
  memcpy(p1->old_ike_spi_r, old_ike_spi_r, 8);

  /* Decode identities. */
  p1->local_id = pm_util_decode_id(local_id, local_id_len);
  if (p1->local_id == NULL && local_id_len > 0)
    goto decode_error;
  p1->remote_id = pm_util_decode_id(remote_id, remote_id_len);
  if (p1->remote_id == NULL && remote_id_len > 0)
    goto decode_error;
  p1->local_auth_method = (SshPmAuthMethod) local_auth_method;
  p1->remote_auth_method = (SshPmAuthMethod) remote_auth_method;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  p1->second_local_id = pm_util_decode_id(second_local_id,
                                          second_local_id_len);
  if (p1->second_local_id == NULL && second_local_id_len > 0)
    goto decode_error;
  p1->second_remote_id = pm_util_decode_id(second_remote_id,
                                           second_remote_id_len);
  if (p1->second_remote_id == NULL && second_remote_id_len > 0)
    goto decode_error;
  p1->second_local_auth_method = (SshPmAuthMethod) second_local_auth_method;
  p1->second_remote_auth_method = (SshPmAuthMethod) second_remote_auth_method;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
  p1->eap_remote_id = pm_util_decode_id(eap_remote_id, eap_remote_id_len);
  if (p1->eap_remote_id == NULL && eap_remote_id_len > 0)
    goto decode_error;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  p1->second_eap_remote_id = pm_util_decode_id(second_eap_remote_id,
                                               second_eap_remote_id_len);
  if (p1->second_eap_remote_id == NULL && second_eap_remote_id_len > 0)
    goto decode_error;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
  if (install->import_flags & SSH_PM_IKE_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK)
    p1->enable_blacklist_check = 1;
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /* Decode authorization group ids. */
  len = ssh_decode_buffer(install->buffer,
                          SSH_DECODE_UINT32(&p1->num_authorization_group_ids),
                          SSH_FORMAT_END);
  if (len != 4)
    goto decode_error;
  if (p1->num_authorization_group_ids)
    {
      if (p1->auth_group_ids_set == 0)
        goto decode_error;

      p1->authorization_group_ids =
        ssh_calloc(p1->num_authorization_group_ids, sizeof(SshUInt32));
      if (p1->authorization_group_ids == NULL)
        {
          error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      for (i = 0; i < p1->num_authorization_group_ids; i++)
        {
          len = ssh_decode_buffer(install->buffer,
                                  SSH_DECODE_UINT32(
                                  &p1->authorization_group_ids[i]),
                                  SSH_FORMAT_END);
          if (len != 4)
            goto decode_error;
        }
    }

  /* Decode XAUTH authorization group ids. */
  len = ssh_decode_buffer(install->buffer,
                          SSH_DECODE_UINT32(
                          &p1->num_xauth_authorization_group_ids),
                          SSH_FORMAT_END);
  if (len != 4)
    goto decode_error;
  if (p1->num_xauth_authorization_group_ids)
    {
      p1->xauth_authorization_group_ids =
        ssh_calloc(p1->num_xauth_authorization_group_ids, sizeof(SshUInt32));
      if (p1->xauth_authorization_group_ids == NULL)
        {
          error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      for (i = 0; i < p1->num_xauth_authorization_group_ids; i++)
        {
          len = ssh_decode_buffer(install->buffer,
                                  SSH_DECODE_UINT32(
                                  &p1->xauth_authorization_group_ids[i]),
                                  SSH_FORMAT_END);
          if (len != 4)
            goto decode_error;
        }
    }

  /* Decode remote access attributes. */
  len = ssh_decode_buffer(install->buffer,
                          SSH_DECODE_UINT32_STR_NOCOPY(&ras_attrs,
                                                       &ras_attrs_len),
                          SSH_FORMAT_END);
  if (len == 0)
    goto decode_error;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  if (ras_attrs_len > 0
      && pm_util_decode_p1_ras_attrs(ras_attrs, ras_attrs_len,
                                     install->remote_access_attrs) == FALSE)
    goto decode_error;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  /* Decode the ike library part of IKE SA. */
  len =
    ssh_decode_buffer(install->buffer,
                      SSH_DECODE_UINT32_STR_NOCOPY(
                      &install->encoded_ike_sa, &install->encoded_ike_sa_len),
                      SSH_FORMAT_END);
  if (len == 0)
    goto decode_error;

  if (tunnel_app_id_len > 0)
    {
      install->tunnel_app_id = ssh_malloc(tunnel_app_id_len);
      if (install->tunnel_app_id == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed allocation memory for IKE SA's tunnel "
                     "application identifier"));
          goto decode_error;
        }
      memcpy(install->tunnel_app_id, tunnel_app_id, tunnel_app_id_len);
      install->tunnel_app_id_len = tunnel_app_id_len;
    }

  /* Check if there is unparsed data left in the buffer. */
  if (ssh_buffer_len(install->buffer))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("IKE SA import buffer has %d bytes trailing garbage",
                 ssh_buffer_len(install->buffer)));
      goto decode_error;
    }

  /* Check IKE SA expiration. */
  if (p1->expire_time < ssh_time())
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA %p has already expired", p1));
      error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;
      goto error;
    }

  SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
  SSH_DEBUG(SSH_D_LOWOK, ("Starting FSM thread for IKE SA import"));

  ssh_fsm_thread_init(&pm->fsm, &install->thread,
                      pm_st_ike_sa_import_start,
                      NULL_FNPTR,
                      pm_ike_sa_import_destructor,
                      install);

  /* IKE SA import cannot be aborted. */
  return NULL;

  /* Error handling. */
 decode_error:
  SSH_DEBUG(SSH_D_FAIL, ("IKE SA decode failed"));
  error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;

 error:
  SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);
  if (status_callback)
    (*status_callback)(pm, error, NULL, status_callback_context);

  if (p1)
    ssh_pm_p1_free(pm, p1);
  if (install)
    {
      if (install->remote_access_attrs->server_duid != NULL)
        ssh_free(install->remote_access_attrs->server_duid);
      ssh_free(install->tunnel_app_id);
      ssh_free(install);
    }

  return NULL;
}


SshPmSAImportStatus
ssh_pm_ike_sa_decode_deleted_event(SshBuffer buffer,
                                   SshUInt32 *ike_version_ret,
                                   unsigned char *ike_spi_i_ret,
                                   unsigned char *ike_spi_r_ret)
{
  size_t offset;
  SshUInt32 version, type, ike_version;

  if (buffer == NULL
      || ike_version_ret == NULL
      || ike_spi_i_ret == NULL
      || ike_spi_r_ret == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_UINT32(&version),
                             SSH_DECODE_UINT32(&type),
                             SSH_FORMAT_END);
  if (offset == 0
      || version != SSH_PM_SA_EXPORT_VERSION
      || type != SSH_PM_SA_EXPORT_IKE_SA_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA export header"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_UINT32(&ike_version),
                             SSH_DECODE_DATA(ike_spi_i_ret, (size_t) 8),
                             SSH_DECODE_DATA(ike_spi_r_ret, (size_t) 8),
                             SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA destroyed event decode failed"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  if (ike_version != 2
#ifdef SSHDIST_IKEV1
       && ike_version != 1
#endif /* SSHDIST_IKEV1 */
      )
    {
      SSH_DEBUG(SSH_D_FAIL, ("Corrupted IKE SA destroyed event"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  *ike_version_ret = ike_version;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Decoded IKEv%d SA I%02x%02x%02x%02x %02x%02x%02x%02x "
             "R%02x%02x%02x%02x %02x%02x%02x%02x",
             ike_version,
             ike_spi_i_ret[0], ike_spi_i_ret[1], ike_spi_i_ret[2],
             ike_spi_i_ret[3], ike_spi_i_ret[4], ike_spi_i_ret[5],
             ike_spi_i_ret[6], ike_spi_i_ret[7],
             ike_spi_r_ret[0], ike_spi_r_ret[1], ike_spi_r_ret[2],
             ike_spi_r_ret[3], ike_spi_r_ret[4], ike_spi_r_ret[5],
             ike_spi_r_ret[6], ike_spi_r_ret[7]));

  return SSH_PM_SA_IMPORT_OK;
}


/***************************** IPsec SA export *******************************/

/* Flag values for IPsec SA import flags. */
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD           0x0001
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED                0x0002
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE         0x0004
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS    0x0008
#define SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK 0x0010

/* Context data for IPsec SA import/export */
typedef struct SshPmImportIpsecInstallRec
{
  Boolean done;
  SshPmSAImportStatus error;
  SshPm pm;
  SshPmQm qm;
  SshFSMThreadStruct thread;
  SshPmIpsecSAPreImportCB import_cb;
  void *import_context;
  SshPmIpsecSAImportStatusCB status_cb;
  void *status_context;

  /* Fields filled in by pm_ipsec_sa_decode(). */
  SshUInt32 tunnel_id;
  SshUInt32 rule_id;
  SshUInt32 import_flags;
  SshUInt32 life_seconds;
  SshTime expire_time;
  unsigned char ike_spi_i[8];
  unsigned char ike_spi_r[8];
  SshIkev2PayloadID local_ike_id;
  SshIkev2PayloadID remote_ike_id;
  unsigned char *tunnel_app_id;
  size_t tunnel_app_id_len;
  unsigned char *outer_tunnel_app_id;
  size_t outer_tunnel_app_id_len;
  unsigned char *rule_app_id;
  size_t rule_app_id_len;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  const void *radius_acct_context;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

} SshPmImportIpsecInstallStruct, *SshPmImportIpsecInstall;


/* Encode IPsec SA to `buffer'. */
static size_t
pm_ipsec_sa_encode(SshPm pm,
                   SshPmQm qm,
                   SshIkev2PayloadID local_id,
                   SshIkev2PayloadID remote_id,
                   unsigned char *ike_spi_i,
                   unsigned char *ike_spi_r,
                   SshBuffer buffer,
                   SshTime expire_time,
                   SshUInt32 import_flags)
{
  unsigned char exported_trc[64 + SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH];
  unsigned char exported_trd[512];
  size_t exported_trc_len,  exported_trd_len;
  unsigned char *exported_local_ts = NULL;
  unsigned char *exported_remote_ts = NULL;
  size_t exported_local_ts_len, exported_remote_ts_len;
  SshEngineTransformData trd;
  SshEngineTransformControl trc;
  size_t len, total_len;
  unsigned char *peer_id = NULL;
  size_t peer_id_len = 0;
  SshUInt32 life_kilobytes = 0;
  unsigned char *tcp_encaps_conn_spi = NULL;
  size_t tcp_encaps_conn_spi_len = 0;
  SshUInt8 natt_flags = 0;
  unsigned char *natt_oa_l = NULL;
  unsigned char *natt_oa_r = NULL;
  size_t natt_oa_len = 0;
  unsigned char *exported_local_ike_id = NULL;
  size_t exported_local_ike_id_len = 0;
  unsigned char *exported_remote_ike_id = NULL;
  size_t exported_remote_ike_id_len = 0;
  unsigned char *tunnel_app_id = NULL;
  size_t tunnel_app_id_len = 0;
  unsigned char *rule_app_id;
  size_t rule_app_id_len = 0;

  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(ike_spi_i != NULL);
  SSH_ASSERT(ike_spi_r != NULL);

  trd = &qm->sa_handler_data.trd.data;
  trc = &qm->sa_handler_data.trd.control;

  /* Check IPsec SA. */
  if (trd->transform & SSH_PM_IPSEC_MANUAL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Can't export manual keyed IPsec SA"));
      return 0;
    }
  if (trd->transform & SSH_PM_IPSEC_L2TP)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Can't export IPsec SA with L2tp transform"));
      return 0;
    }

  /* Encode SshEngineTransformControl. */

  if (trc->outer_tunnel_id > 0)
    {
      SshPmTunnel outer_tunnel;

      outer_tunnel = ssh_pm_tunnel_get_by_id(pm, trc->outer_tunnel_id);
      if (outer_tunnel == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid outer_tunnel_id %d",
                                 (int) trc->outer_tunnel_id));
          return 0;
        }
      tunnel_app_id = outer_tunnel->application_identifier;
      tunnel_app_id_len = outer_tunnel->application_identifier_len;
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  peer_id = trc->peer_id;
  peer_id_len = sizeof(trc->peer_id);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_STATISTICS
  life_kilobytes = qm->trd_life_kilobytes;
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSH_IPSEC_TCPENCAP
  tcp_encaps_conn_spi = trc->tcp_encaps_conn_spi;
  tcp_encaps_conn_spi_len = sizeof(trc->tcp_encaps_conn_spi);
#endif /* SSH_IPSEC_TCPENCAP */

  /* Export expiry time. */
  if (expire_time == 0)
    expire_time = ssh_time() + qm->trd_life_seconds;

  exported_trc_len =
    ssh_encode_array(exported_trc, sizeof(exported_trc),
                     SSH_ENCODE_UINT32_STR(peer_id, peer_id_len),
                     SSH_ENCODE_UINT32(trc->control_flags),
                     SSH_ENCODE_UINT32(trc->outer_tunnel_id),
                     SSH_ENCODE_UINT32_STR(tunnel_app_id, tunnel_app_id_len),
                     SSH_ENCODE_UINT32(life_kilobytes),
                     SSH_ENCODE_UINT32(qm->trd_life_seconds),
                     SSH_ENCODE_UINT64(expire_time),
                     SSH_ENCODE_UINT32_STR(tcp_encaps_conn_spi,
                                           tcp_encaps_conn_spi_len),
                     SSH_FORMAT_END);
  if (exported_trc_len == 0)
    goto encode_error;

  /* Encode SshEngineTransformData. */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  natt_flags = trd->natt_flags;
  natt_oa_l = trd->natt_oa_l;
  natt_oa_r = trd->natt_oa_r;
  natt_oa_len = SSH_IP_ADDR_SIZE;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  exported_trd_len =
    ssh_encode_array(exported_trd, sizeof(exported_trd),
                     SSH_ENCODE_UINT64(trd->transform),
                     SSH_ENCODE_UINT32(trd->spis[0]),
                     SSH_ENCODE_UINT32(trd->spis[1]),
                     SSH_ENCODE_UINT32(trd->spis[2]),
                     SSH_ENCODE_UINT32(trd->spis[3]),
                     SSH_ENCODE_UINT32(trd->spis[4]),
                     SSH_ENCODE_UINT32(trd->spis[5]),
                     SSH_ENCODE_UINT32(trd->out_packets_high),
                     SSH_ENCODE_UINT32(trd->out_packets_low),
                     SSH_ENCODE_UINT32(trd->replay_offset_high),
                     SSH_ENCODE_UINT32(trd->replay_offset_low),
                     SSH_ENCODE_DATA((const unsigned char *) trd->replay_mask,
                                     sizeof(trd->replay_mask)),
                     SSH_ENCODE_UINT16(trd->local_port),
                     SSH_ENCODE_UINT16(trd->remote_port),
                     SSH_ENCODE_CHAR(natt_flags),
                     SSH_ENCODE_UINT32_STR(natt_oa_l, natt_oa_len),
                     SSH_ENCODE_UINT32_STR(natt_oa_r, natt_oa_len),
                     SSH_ENCODE_UINT32(trd->inbound_tunnel_id),
                     SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                        &trd->gw_addr),
                     SSH_ENCODE_SPECIAL(ssh_encode_ipaddr_encoder,
                                        &trd->own_addr),
                     SSH_ENCODE_UINT32((SshUInt32) trd->own_ifnum),
                     SSH_ENCODE_CHAR(trd->df_bit_processing),
                     SSH_ENCODE_UINT16(trd->packet_enlargement),
                     SSH_ENCODE_UINT32_STR(trd->keymat, sizeof(trd->keymat)),
                     SSH_ENCODE_UINT16(trd->cipher_key_size),
                     SSH_ENCODE_UINT16(trd->cipher_iv_size),
                     SSH_ENCODE_UINT16(trd->cipher_nonce_size),
                     SSH_ENCODE_UINT16(trd->mac_key_size),
                     SSH_FORMAT_END);
  if (exported_trd_len == 0)
    goto encode_error;

  exported_local_ts =
    pm_util_encode_ts(qm->local_ts, &exported_local_ts_len);
  exported_remote_ts =
    pm_util_encode_ts(qm->remote_ts, &exported_remote_ts_len);
  if (exported_local_ts == NULL || exported_remote_ts == NULL)
    goto encode_error;

  /* Encode fixed IPsec SA export header. */
  len = ssh_encode_buffer(buffer,
                          SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                          SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IPSEC_SA),
                          SSH_FORMAT_END);
  if (len == 0)
    goto encode_error;
  total_len = len;

  /* Encode rest. */

  exported_local_ike_id = pm_util_encode_id(local_id,
                                            &exported_local_ike_id_len);
  if (exported_local_ike_id == NULL && local_id != NULL)
    goto encode_error;
  exported_remote_ike_id = pm_util_encode_id(remote_id,
                                             &exported_remote_ike_id_len);
  if (exported_remote_ike_id == NULL && remote_id != NULL)
    goto encode_error;

  if (qm->forward)
    import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD;

  if (qm->rekey)
    import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED;

  if (qm->transport_sent && qm->transport_recv)
    import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE;

#ifdef SSH_PM_BLACKLIST_ENABLED
  {
    SshPmPeer peer;

    peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
    if (peer != NULL && peer->enable_blacklist_check)
      import_flags |= SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK;
  }
#endif /* SSH_PM_BLACKLIST_ENABLED */

  tunnel_app_id = qm->tunnel->application_identifier;
  tunnel_app_id_len = qm->tunnel->application_identifier_len;
  rule_app_id = qm->rule->application_identifier;
  rule_app_id_len = qm->rule->application_identifier_len;

  len =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32_STR(ike_spi_i, 8),
                      SSH_ENCODE_UINT32_STR(ike_spi_r, 8),
                      SSH_ENCODE_UINT32_STR(exported_local_ike_id,
                                            exported_local_ike_id_len),
                      SSH_ENCODE_UINT32_STR(exported_remote_ike_id,
                                            exported_remote_ike_id_len),
                      SSH_ENCODE_UINT32(import_flags),
                      SSH_ENCODE_UINT32(qm->tunnel->tunnel_id),
                      SSH_ENCODE_UINT32(qm->rule->rule_id),
                      SSH_ENCODE_UINT32_STR(tunnel_app_id, tunnel_app_id_len),
                      SSH_ENCODE_UINT32_STR(rule_app_id, rule_app_id_len),
                      SSH_ENCODE_UINT32_STR(exported_local_ts,
                                            exported_local_ts_len),
                      SSH_ENCODE_UINT32_STR(exported_remote_ts,
                                            exported_remote_ts_len),
                      SSH_ENCODE_UINT32_STR(exported_trc, exported_trc_len),
                      SSH_ENCODE_UINT32_STR(exported_trd, exported_trd_len),
                      SSH_FORMAT_END);
  if (len == 0)
    goto encode_error;
  total_len += len;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  len = pm_radius_acct_encode_session(buffer, qm->p1);
  if (len == 0)
    {
      goto encode_error;
    }
  total_len += len;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  ssh_free(exported_remote_ts);
  ssh_free(exported_local_ts);
  ssh_free(exported_remote_ike_id);
  ssh_free(exported_local_ike_id);

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA %@ exported, len %d",
                          pm_ipsec_spi_render, qm, total_len));

  return total_len;

 encode_error:
  SSH_DEBUG(SSH_D_FAIL, ("IPsec SA %@ encode failed",
                         pm_ipsec_spi_render, qm));
  ssh_free(exported_remote_ts);
  ssh_free(exported_local_ts);
  ssh_free(exported_remote_ike_id);
  ssh_free(exported_local_ike_id);

  return 0;
}

static size_t
pm_ipsec_sa_encode_deleted_event(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa,
                                 SshBuffer buffer)
{
  size_t total_len;

  /* Encode fixed IPsec SA export header, IP protocol and SPI values. */
  total_len =
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_VERSION),
                      SSH_ENCODE_UINT32(SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED),
                      SSH_ENCODE_CHAR(ipsec_sa->ipproto),
                      SSH_ENCODE_UINT32(ipsec_sa->inbound_spi),
                      SSH_ENCODE_UINT32(ipsec_sa->outbound_spi),
                      SSH_FORMAT_END);
  if (total_len == 0)
    goto encode_error;

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA %@-%08lx destroyed event encoded",
                          ssh_ipproto_render, (SshUInt32) ipsec_sa->ipproto,
                          (unsigned long) ipsec_sa->inbound_spi));

  return total_len;

 encode_error:
  SSH_DEBUG(SSH_D_FAIL, ("IPsec SA %@-%08lx destroyed event encode failed",
                         ssh_ipproto_render, (SshUInt32) ipsec_sa->ipproto,
                         (unsigned long) ipsec_sa->inbound_spi));
  return 0;
}

size_t
ssh_pm_ipsec_sa_export(SshPm pm,
                       SshPmIPsecSAEventHandle ipsec_sa,
                       SshBuffer buffer)
{
  /* Check input parameters. */
  if (ipsec_sa == NULL || buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      return 0;
    }

  /* Check IPsec SA event. */
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:




      if ((ipsec_sa->qm == NULL || ipsec_sa->qm->p1 == NULL)
          && ipsec_sa->import_context == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA event handle"));
          return 0;
        }

      if (ipsec_sa->qm != NULL && ipsec_sa->qm->p1 != NULL)
        {
          return pm_ipsec_sa_encode(pm, ipsec_sa->qm,
                                    ipsec_sa->qm->p1->local_id,
                                    ipsec_sa->qm->p1->remote_id,
                                    ipsec_sa->qm->p1->ike_sa->ike_spi_i,
                                    ipsec_sa->qm->p1->ike_sa->ike_spi_r,
                                    buffer,
                                    ipsec_sa->expire_time, 0);
        }
      else
        {
          SshPmImportIpsecInstall install = ipsec_sa->import_context;

          SSH_ASSERT(install != NULL);

          return pm_ipsec_sa_encode(pm, ipsec_sa->qm,
                                    install->local_ike_id,
                                    install->remote_ike_id,
                                    install->ike_spi_i,
                                    install->ike_spi_r,
                                    buffer,
                                    ipsec_sa->expire_time, 0);
        }

    case SSH_PM_SA_EVENT_DELETED:
      return pm_ipsec_sa_encode_deleted_event(pm, ipsec_sa, buffer);

    case SSH_PM_SA_EVENT_UPDATED:
      SSH_DEBUG(SSH_D_FAIL, ("Can't export IPsec SA UPDATED event"));
      break;
    }

  return 0;
}

/***************************** IPsec SA import *******************************/

/* Uninitialize contents of install. Note that this does not free install,
   as it might be allocated from stack. */
void
pm_ipsec_sa_import_uninit_install(SshPmImportIpsecInstall install)
{
  if (install->local_ike_id)
    ssh_pm_ikev2_payload_id_free(install->local_ike_id);
  if (install->remote_ike_id)
    ssh_pm_ikev2_payload_id_free(install->remote_ike_id);
  ssh_free(install->tunnel_app_id);
  ssh_free(install->outer_tunnel_app_id);
  ssh_free(install->rule_app_id);
}

/* Setup rule and tunnel references to 'qm'. */
SshPmSAImportStatus
pm_ipsec_sa_import_prepare_qm(SshPm pm, SshPmQm qm, SshUInt32 tunnel_id,
                              SshUInt32 rule_id)
{
  if (qm->tunnel == NULL)
    {
      qm->tunnel = ssh_pm_tunnel_get_by_id(pm, tunnel_id);
      if (qm->tunnel == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not find tunnel (id %d) for imported IPsec SA",
                     (int) tunnel_id));
          return SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        }
      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
    }

  if (qm->rule == NULL)
    {
      qm->rule = ssh_pm_rule_lookup(pm, rule_id);
      if (qm->rule == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not find rule (id %d) for imported IPsec SA",
                     (int) rule_id));
          return SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
        }
      SSH_PM_RULE_LOCK(qm->rule);
    }

  return SSH_PM_SA_IMPORT_OK;
}

/* FSM state declarations */
SSH_FSM_STEP(pm_st_ipsec_sa_import_start);
SSH_FSM_STEP(pm_st_ipsec_sa_import_install);
SSH_FSM_STEP(pm_st_ipsec_sa_import_invalidate_old_spis);
SSH_FSM_STEP(pm_st_ipsec_sa_import_terminate);

void pm_ipsec_sa_import_destructor(SshFSM fsm, void *context)
{
  SshPmImportIpsecInstall install = context;

  if (install->qm != NULL)
    ssh_pm_qm_free(install->pm, install->qm);

  pm_ipsec_sa_import_uninit_install(install);
  ssh_free(install);
}

/* Callback function for pre import hook */
static void
pm_ipsec_sa_import_hook_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmImportIpsecInstall install =
    (SshPmImportIpsecInstall) ssh_fsm_get_tdata(thread);

  if (!success)
    {
      install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      ssh_fsm_set_next(thread, pm_st_ipsec_sa_import_terminate);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Callback function for IPsec SA installation */
static void
pm_ipsec_sa_import_done(SshIkev2Error status,
                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmImportIpsecInstall install =
    (SshPmImportIpsecInstall) ssh_fsm_get_tdata(thread);

  if (status == SSH_IKEV2_ERROR_OK)
    {
      install->done = TRUE;
    }
  else
    {
      switch (status)
        {
        case SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION:
        case SSH_IKEV2_ERROR_INVALID_SYNTAX:
        case SSH_IKEV2_ERROR_INVALID_ARGUMENT:
          install->error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
          break;

        case SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN:
        case SSH_IKEV2_ERROR_AUTHENTICATION_FAILED:
        case SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE:
        case SSH_IKEV2_ERROR_USE_IKEV1:
          install->error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
          break;

        default:
          install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
        }

      SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA %@",
                             pm_ipsec_spi_render, install->qm));

      /* qm is freed in the qm_sub_thread_destructor. */
      install->qm = NULL;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Call import hook function */
SSH_FSM_STEP(pm_st_ipsec_sa_import_start)
{
  SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
  SshPmIPsecSAEventHandleStruct ipsec_sa;

  if (install->import_flags
      & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
    {
      SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_invalidate_old_spis);
      return SSH_FSM_CONTINUE;
    }

  /* Call pre-import hook for updating imported IPsec SA data. */
  SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_install);
  if (install->import_cb != NULL_FNPTR && !install->qm->aborted)
    {
      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
      ipsec_sa.qm = install->qm;
      ipsec_sa.life_seconds = install->life_seconds;
      ipsec_sa.tunnel_application_identifier = install->tunnel_app_id;
      ipsec_sa.tunnel_application_identifier_len = install->tunnel_app_id_len;
      ipsec_sa.outer_tunnel_application_identifier =
        install->outer_tunnel_app_id;
      ipsec_sa.outer_tunnel_application_identifier_len =
        install->outer_tunnel_app_id_len;
      ipsec_sa.rule_application_identifier = install->rule_app_id;
      ipsec_sa.rule_application_identifier_len = install->rule_app_id_len;
      ipsec_sa.import_context = install;

      SSH_FSM_ASYNC_CALL({
          (*install->import_cb)(install->pm,
                                &ipsec_sa,
                                pm_ipsec_sa_import_hook_cb,
                                thread,
                                install->import_context);
        });
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

/* Install IPsec SA */
SSH_FSM_STEP(pm_st_ipsec_sa_import_install)
{
  SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
  SshPm pm = install->pm;
  SshPmQm qm = install->qm;
  SshEngineTransformData trd = &install->qm->sa_handler_data.trd.data;

  SSH_ASSERT((install->import_flags
              & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS) == 0);

  SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_terminate);

  if (install->qm->aborted)
    {
      /* If qm was aborted then fail with no IKE SA found. */
      install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  if (install->radius_acct_context != NULL)
    {
      SshPmActiveCfgModeClient client = NULL;

      if (install->qm->p1 != NULL)
        {
          client = install->qm->p1->cfgmode_client;
        }
      else
        {
          SshUInt32 peer_handle = install->qm->peer_handle;

          if (peer_handle != SSH_IPSEC_INVALID_INDEX)
            {
              client =
                  ssh_pm_cfgmode_client_store_lookup(
                          install->pm,
                          peer_handle);
            }
          else
            {
              SSH_DEBUG(
                      SSH_D_FAIL,
                      ("No peer handle for RADIUS Accounting session!"));

            }
        }

      if (client != NULL)
        {
          pm_radius_acct_install_session(
                  client,
                  install->radius_acct_context);
        }
      else
        {
          SSH_DEBUG(
                  SSH_D_FAIL,
                  ("No cfgmode client for RADIUS Accounting session!"));
        }
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  /* Set rule and tunnel references to qm if application has not set them
     via import/export API. */
  install->error = pm_ipsec_sa_import_prepare_qm(pm, qm,
                                                 install->tunnel_id,
                                                 install->rule_id);
  if (install->error != SSH_PM_SA_IMPORT_OK)
    return SSH_FSM_CONTINUE;

  /* Lookup or create peer for parentless IKEv1 keyed IPsec SAs. */
  SSH_ASSERT(qm->peer_handle == SSH_IPSEC_INVALID_INDEX);
  if (qm->p1 == NULL)
    {
      SSH_ASSERT(qm->sa_handler_data.trd.control.control_flags &
                 SSH_ENGINE_TR_C_IKEV1_SA);

      /* Lookup a peer object for IKEv1 keyed IPsec SAs that have no
         parent IKE SA anymore. */
      qm->peer_handle =
        ssh_pm_peer_handle_lookup(pm,
                                  &trd->gw_addr, trd->remote_port,
                                  &trd->own_addr, trd->local_port,
                                  install->remote_ike_id,
                                  install->local_ike_id,
                                  qm->tunnel->routing_instance_id,
                                  TRUE, FALSE);
      if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
          /* Take a reference to peer handle for protecting
             qm->peer_handle. */
          ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
      else
        {
          SshUInt32 flags = SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;

#ifdef SSH_PM_BLACKLIST_ENABLED
          if (install->import_flags
              & SSH_PM_IPSEC_SA_IMPORT_FLAG_ENABLE_BLACKLIST_CHECK)
            flags |= SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK;
#endif /* SSH_PM_BLACKLIST_ENABLED */






          /* No matching peer found, create new peer. The function returns
             with one reference taken to the peer object. use that reference
             to protect qm->peer_handle. */
          qm->peer_handle =
            ssh_pm_peer_create_internal(pm,
                                        &trd->gw_addr, trd->remote_port,
                                        &trd->own_addr, trd->local_port,
                                        install->local_ike_id,
                                        install->remote_ike_id,
                                        SSH_IPSEC_INVALID_INDEX,
                                        qm->tunnel->routing_instance_id,
                                        flags, FALSE);
        }

      if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could create peer object for parentless IPsec SA"));
          install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
          return SSH_FSM_CONTINUE;
        }
    }

  /* Register the inbound SPI's with the policy manager. We require them to
     be unique. The outbound SPI's are registered after the engine transform
     is created. Copy the SPI's to qm where they will get freed if the qm
     installation fails. */
  qm->spis[0] = trd->spis[0];
  qm->spis[1] = trd->spis[1];
  qm->spis[2] = trd->spis[2];

  if (ssh_pm_register_inbound_spis(pm, qm->spis) == FALSE)
    {
      install->error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_ASYNC_CALL({
      ssh_pm_ipsec_sa_install_qm(pm, qm->p1, qm,
                                 pm_ipsec_sa_import_done, thread);
    });
  SSH_NOTREACHED;
}

/* Invalidate old SPI values */
SSH_FSM_STEP(pm_st_ipsec_sa_import_invalidate_old_spis)
{
  SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
  SshPm pm = install->pm;
  SshPmQm qm = install->qm;
  SshEngineTransformData trd = &install->qm->sa_handler_data.trd.data;
  SshUInt32 inbound_spi = 0, outbound_spi = 0;
  SshUInt8 ipproto = 0;

  SSH_ASSERT(install->import_flags
             & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS);

  SSH_FSM_SET_NEXT(pm_st_ipsec_sa_import_terminate);

  if (install->qm->aborted)
    {
      /* If qm was aborted then fail with no IKE SA found. */
      install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
      return SSH_FSM_CONTINUE;
    }

  /* Set rule and tunnel references to qm if application has not set them
     via import/export API. */
  install->error = pm_ipsec_sa_import_prepare_qm(pm, qm,
                                                 install->tunnel_id,
                                                 install->rule_id);
  if (install->error != SSH_PM_SA_IMPORT_OK)
    return SSH_FSM_CONTINUE;

  /* Lookup peer_handle for the IKE SA. */
  SSH_ASSERT(qm->peer_handle == SSH_IPSEC_INVALID_INDEX);
  if (qm->p1 != NULL)
    {
      qm->peer_handle = ssh_pm_peer_handle_by_p1(pm, qm->p1);
      if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
          /* Take a reference to peer handle for protecting
             qm->peer_handle. */
          ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
      else
        {
          /* No peer found, create a peer object temporarily. Use the
             returned peer handle reference for protecting
             qm->peer_handle. */
          qm->peer_handle =
            ssh_pm_peer_create(pm,
                               &trd->gw_addr,
                               qm->p1->ike_sa->remote_port,
                               &trd->own_addr,
                               SSH_PM_IKE_SA_LOCAL_PORT(qm->p1->ike_sa),
                               qm->p1, FALSE,
                               qm->tunnel->routing_instance_id);
        }
    }

  /* Lookup or create peer for parentless IKEv1 keyed IPsec SAs. */
  else
    {
      SSH_ASSERT(qm->sa_handler_data.trd.control.control_flags &
                 SSH_ENGINE_TR_C_IKEV1_SA);

      /* Lookup a peer object for IKEv1 keyed IPsec SAs that have no
         parent IKE SA anymore. */
      qm->peer_handle =
        ssh_pm_peer_handle_lookup(pm,
                                  &trd->gw_addr, trd->remote_port,
                                  &trd->own_addr, trd->local_port,
                                  install->remote_ike_id,
                                  install->local_ike_id,
                                  qm->tunnel->routing_instance_id,
                                  TRUE, FALSE);

      if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
          /* Take a reference to peer handle for protecting
             qm->peer_handle. */
          ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);
        }
      else
        {
          SshUInt32 flags = SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1;






          /* No matching peer found, create new peer. The function returns
             with one reference taken to the peer object. use that reference
             to protect qm->peer_handle. */
          qm->peer_handle =
              ssh_pm_peer_create_internal(pm,
                                        &trd->gw_addr, trd->remote_port,
                                        &trd->own_addr, trd->local_port,
                                        install->local_ike_id,
                                        install->remote_ike_id,
                                        SSH_IPSEC_INVALID_INDEX,
                                        qm->tunnel->routing_instance_id,
                                        flags, FALSE);
        }

      if (qm->peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could create peer object for parentless IPsec SA"));
          install->error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
          return SSH_FSM_CONTINUE;
        }
    }

  /* Send delete notification for the inbound SPI value. */
  if (trd->spis[SSH_PME_SPI_ESP_IN] != 0)
    {
      inbound_spi = trd->spis[SSH_PME_SPI_ESP_IN];
      outbound_spi = trd->spis[SSH_PME_SPI_ESP_OUT];
      ipproto = SSH_IPPROTO_ESP;
    }
  else if (trd->spis[SSH_PME_SPI_AH_IN] != 0)
    {
      inbound_spi = trd->spis[SSH_PME_SPI_AH_IN];
      outbound_spi = trd->spis[SSH_PME_SPI_AH_OUT];
      ipproto = SSH_IPPROTO_AH;
    }
  else
    SSH_NOTREACHED;

  ssh_pm_send_ipsec_delete_notification(pm,
                                        qm->peer_handle,
                                        qm->tunnel,
                                        qm->rule,
                                        ipproto, 1, &inbound_spi);

  /* Generate a deleted event for the IPsec SA. */
  ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi, inbound_spi, ipproto);

  install->done = TRUE;
  install->error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;

  return SSH_FSM_CONTINUE;
}

/* Terminate state machine and call completion callback */
SSH_FSM_STEP(pm_st_ipsec_sa_import_terminate)
{
  SshPmImportIpsecInstall install = (SshPmImportIpsecInstall) thread_context;
  SshEngineTransformData trd = &install->qm->sa_handler_data.trd.data;
  SshPmIPsecSAEventHandleStruct ipsec_sa;

  if (!install->done)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA"));

      SSH_ASSERT(install->error != SSH_PM_SA_IMPORT_OK);

      if (install->status_cb != NULL_FNPTR)
        (*install->status_cb)(install->pm,
                              install->error, NULL,
                              install->status_context);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA %@ imported",
                              pm_ipsec_spi_render, install->qm));

      if (install->status_cb != NULL_FNPTR)
        {
          /* Pass the IPsec SA handle to application so that the possibly
             changed SA data can be re-exported. */
          memset(&ipsec_sa, 0, sizeof(ipsec_sa));
          ipsec_sa.import_context = install;

          if (install->import_flags
              & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
            {
              ipsec_sa.event = SSH_PM_SA_EVENT_DELETED;
              if (install->qm->transform & SSH_PM_IPSEC_AH)
                {
                  ipsec_sa.inbound_spi = trd->spis[SSH_PME_SPI_AH_IN];
                  ipsec_sa.outbound_spi = trd->spis[SSH_PME_SPI_AH_OUT];
                  ipsec_sa.ipproto = SSH_IPPROTO_AH;
                }
              else if (install->qm->transform & SSH_PM_IPSEC_ESP)
                {
                  ipsec_sa.inbound_spi = trd->spis[SSH_PME_SPI_ESP_IN];
                  ipsec_sa.outbound_spi = trd->spis[SSH_PME_SPI_ESP_OUT];
                  ipsec_sa.ipproto = SSH_IPPROTO_ESP;
                }
              else
                SSH_NOTREACHED;

              SSH_ASSERT(install->error == SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED);
            }
          else if (install->import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_REKEYED)
            {
              install->qm->rekey = 1;
              ipsec_sa.event = SSH_PM_SA_EVENT_REKEYED;
              ipsec_sa.qm = install->qm;
              ipsec_sa.expire_time = install->expire_time;

              /* Patch SA lifetime to the original negotiated value. */
              ipsec_sa.qm->trd_life_seconds = install->life_seconds;

              SSH_ASSERT(install->error == SSH_PM_SA_IMPORT_OK);
            }
          else
            {
              ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
              ipsec_sa.qm = install->qm;
              ipsec_sa.expire_time = install->expire_time;

              /* Patch SA lifetime to the original negotiated value. */
              ipsec_sa.qm->trd_life_seconds = install->life_seconds;

              SSH_ASSERT(install->error == SSH_PM_SA_IMPORT_OK);
            }

          (*install->status_cb)(install->pm,
                                install->error, &ipsec_sa,
                                install->status_context);

          install->qm->rekey = 0;
        }

      /* Clear the SPI's so they will not be freed when deallocating
         the Quick-Mode. */
      install->qm->spis[SSH_PME_SPI_ESP_IN] = 0;
      install->qm->spis[SSH_PME_SPI_AH_IN] = 0;
      install->qm->spis[SSH_PME_SPI_IPCOMP_IN] = 0;
    }

  return SSH_FSM_FINISH;
}

/* Decode exported IPsec SA from `buffer'. */
static SshPmSAImportStatus
pm_ipsec_sa_decode(SshPm pm,
                   SshBuffer buffer,
                   SshPmQm *qm_ret,
                   SshPmImportIpsecInstall install)
{
  size_t offset;
  SshUInt32 version, type;
  unsigned char *exported_ike_spi_i, *exported_ike_spi_r;
  size_t exported_ike_spi_i_len, exported_ike_spi_r_len;
  unsigned char *exported_trc, *exported_trd;
  size_t exported_trc_len,  exported_trd_len;
  unsigned char *exported_local_ts, *exported_remote_ts;
  size_t exported_local_ts_len, exported_remote_ts_len;
  unsigned char *exported_local_id, *exported_remote_id;
  size_t exported_local_id_len, exported_remote_id_len;
  SshUInt32 exported_rule_id, exported_tunnel_id;
  SshEngineTransformData trd;
  SshEngineTransformControl trc;
  SshPmQm qm = NULL;
  unsigned char *peer_id;
  size_t peer_id_len;
  unsigned char *tcp_encaps_conn_spi;
  size_t tcp_encaps_conn_spi_len;
  SshUInt32 exported_life_kilobytes, exported_life_seconds;
  SshTime exported_expire_time;
  unsigned int natt_flags;
  unsigned char *natt_oa_l, *natt_oa_r;
  size_t natt_oa_l_len, natt_oa_r_len;
  unsigned char *keymat;
  size_t keymat_len;
  SshUInt16 cipher_key_size, cipher_iv_size, cipher_nonce_size, mac_key_size;
  SshUInt32 own_ifnum;
  SshUInt16 packet_enlargement;
  unsigned int df_bit_processing;
  SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
  SshIkev2PayloadID local_id = NULL;
  SshIkev2PayloadID remote_id = NULL;
  SshUInt32 exported_import_flags;
  unsigned char *exported_tunnel_app_id;
  size_t exported_tunnel_app_id_len;
  unsigned char *exported_outer_tunnel_app_id;
  size_t exported_outer_tunnel_app_id_len;
  unsigned char *exported_rule_app_id;
  size_t exported_rule_app_id_len;

  SSH_ASSERT(qm_ret != NULL);
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(install != NULL);

  /* Decode fixed IPsec SA export header. */
  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_UINT32(&version),
                             SSH_DECODE_UINT32(&type),
                             SSH_FORMAT_END);
  if (offset == 0
      || version != SSH_PM_SA_EXPORT_VERSION
      || type != SSH_PM_SA_EXPORT_IPSEC_SA)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA export header"));
      error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
      goto error;
    }

  /* Decode IPsec SA body. */
  offset =
    ssh_decode_buffer(buffer,
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_ike_spi_i,
                                                   &exported_ike_spi_i_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_ike_spi_r,
                                                   &exported_ike_spi_r_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_local_id,
                                                   &exported_local_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_remote_id,
                                                   &exported_remote_id_len),
                      SSH_DECODE_UINT32(&exported_import_flags),
                      SSH_DECODE_UINT32(&exported_tunnel_id),
                      SSH_DECODE_UINT32(&exported_rule_id),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_tunnel_app_id,
                                                  &exported_tunnel_app_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_rule_app_id,
                                                   &exported_rule_app_id_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_local_ts,
                                                   &exported_local_ts_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_remote_ts,
                                                   &exported_remote_ts_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_trc,
                                                   &exported_trc_len),
                      SSH_DECODE_UINT32_STR_NOCOPY(&exported_trd,
                                                   &exported_trd_len),
                      SSH_FORMAT_END);
  if (offset == 0)
    goto decode_error;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  install->radius_acct_context = pm_radius_acct_decode_session(buffer);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  /* Check if there is unparsed data left in the buffer. */
  if (ssh_buffer_len(buffer))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("IPsec SA import buffer has %d bytes trailing garbage",
                 ssh_buffer_len(buffer)));
      goto decode_error;
    }

  if (exported_ike_spi_i_len != 8 || exported_ike_spi_r_len != 8)
    goto decode_error;

  /* Allocate qm */
  qm = ssh_pm_qm_alloc(pm, FALSE);
  if (qm == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate qm for IPsec SA import"));
      error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  qm->import = 1;

  install->rule_id = exported_rule_id;
  install->tunnel_id = exported_tunnel_id;
  install->import_flags = exported_import_flags;

  /* Decode IKE identities. */
  local_id = pm_util_decode_id(exported_local_id, exported_local_id_len);
  if (exported_local_id_len > 0 && local_id == NULL)
    goto decode_error;

  remote_id = pm_util_decode_id(exported_remote_id, exported_remote_id_len);
  if (exported_remote_id_len > 0 && remote_id == NULL)
    goto decode_error;

  /* Decode Traffic Selectors */
  qm->local_ts =
    pm_util_decode_ts(pm, exported_local_ts, exported_local_ts_len);
  if (qm->local_ts == NULL && exported_local_ts_len > 0)
    goto decode_error;
  qm->remote_ts =
    pm_util_decode_ts(pm, exported_remote_ts, exported_remote_ts_len);
  if (qm->remote_ts == NULL && exported_remote_ts_len > 0)
    goto decode_error;

  /* Decode transform control part. */
  trc = &qm->sa_handler_data.trd.control;
  offset =
    ssh_decode_array(exported_trc, exported_trc_len,
                     SSH_DECODE_UINT32_STR_NOCOPY(&peer_id, &peer_id_len),
                     SSH_DECODE_UINT32(&trc->control_flags),
                     SSH_DECODE_UINT32(&trc->outer_tunnel_id),
                     SSH_DECODE_UINT32_STR_NOCOPY
                     (&exported_outer_tunnel_app_id,
                      &exported_outer_tunnel_app_id_len),
                     SSH_DECODE_UINT32(&exported_life_kilobytes),
                     SSH_DECODE_UINT32(&exported_life_seconds),
                     SSH_DECODE_UINT64(&exported_expire_time),
                     SSH_DECODE_UINT32_STR_NOCOPY
                     (&tcp_encaps_conn_spi, &tcp_encaps_conn_spi_len),
                     SSH_FORMAT_END);
  if (offset != exported_trc_len)
    goto decode_error;

  trc->control_flags |= SSH_ENGINE_TR_C_RECOVERED_SA;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (peer_id_len != sizeof(trc->peer_id))
    goto decode_error;
  memcpy(trc->peer_id, peer_id, peer_id_len);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  install->life_seconds = exported_life_seconds;
  install->expire_time = exported_expire_time;

  qm->trd_life_seconds = exported_life_seconds;

#ifdef SSH_IPSEC_STATISTICS
  /* Kilobyte lifetime is set to negotiated value. It should be fixed up
     later when fixing outbound sequence numbers. */
  qm->trd_life_kilobytes = exported_life_kilobytes;
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSH_IPSEC_TCPENCAP
  if (tcp_encaps_conn_spi_len != 8)
    goto decode_error;
  memcpy(trc->tcp_encaps_conn_spi, tcp_encaps_conn_spi, 8);
#endif /* SSH_IPSEC_TCPENCAP */

  /* Decode transform data part. */
  trd = &qm->sa_handler_data.trd.data;

  offset =
    ssh_decode_array(exported_trd, exported_trd_len,
                     SSH_DECODE_UINT64(&trd->transform),
                     SSH_DECODE_UINT32(&trd->spis[0]),
                     SSH_DECODE_UINT32(&trd->spis[1]),
                     SSH_DECODE_UINT32(&trd->spis[2]),
                     SSH_DECODE_UINT32(&trd->spis[3]),
                     SSH_DECODE_UINT32(&trd->spis[4]),
                     SSH_DECODE_UINT32(&trd->spis[5]),
                     SSH_DECODE_UINT32(&trd->out_packets_high),
                     SSH_DECODE_UINT32(&trd->out_packets_low),
                     SSH_DECODE_UINT32(&trd->replay_offset_high),
                     SSH_DECODE_UINT32(&trd->replay_offset_low),
                     SSH_DECODE_DATA((unsigned char *) trd->replay_mask,
                                     sizeof(trd->replay_mask)),
                     SSH_DECODE_UINT16(&trd->local_port),
                     SSH_DECODE_UINT16(&trd->remote_port),
                     SSH_DECODE_CHAR(&natt_flags),
                     SSH_DECODE_UINT32_STR_NOCOPY(&natt_oa_l, &natt_oa_l_len),
                     SSH_DECODE_UINT32_STR_NOCOPY(&natt_oa_r, &natt_oa_r_len),
                     SSH_DECODE_UINT32(&trd->inbound_tunnel_id),
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                &trd->gw_addr),
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_decode_ipaddr_array,
                                                &trd->own_addr),
                     SSH_DECODE_UINT32(&own_ifnum),
                     SSH_DECODE_CHAR(&df_bit_processing),
                     SSH_DECODE_UINT16(&packet_enlargement),
                     SSH_DECODE_UINT32_STR_NOCOPY(&keymat, &keymat_len),
                     SSH_DECODE_UINT16(&cipher_key_size),
                     SSH_DECODE_UINT16(&cipher_iv_size),
                     SSH_DECODE_UINT16(&cipher_nonce_size),
                     SSH_DECODE_UINT16(&mac_key_size),
                     SSH_FORMAT_END);
  if (offset != exported_trd_len)
    goto decode_error;

  if (keymat_len != sizeof(trd->keymat))
    goto decode_error;
  memcpy(trd->keymat, keymat, keymat_len);

  SSH_ASSERT(cipher_key_size < 256);
  SSH_ASSERT(cipher_iv_size < 256);
  SSH_ASSERT(cipher_nonce_size < 256);
  SSH_ASSERT(mac_key_size < 256);

  trd->cipher_key_size = (SshUInt8)cipher_key_size;
  trd->cipher_iv_size = (SshUInt8)cipher_iv_size;
  trd->cipher_nonce_size = (SshUInt8)cipher_nonce_size;
  trd->mac_key_size = (SshUInt8)mac_key_size;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (natt_oa_l_len != SSH_IP_ADDR_SIZE || natt_oa_r_len != SSH_IP_ADDR_SIZE)
    goto decode_error;
  memcpy(trd->natt_oa_l, natt_oa_l, SSH_IP_ADDR_SIZE);
  memcpy(trd->natt_oa_r, natt_oa_r, SSH_IP_ADDR_SIZE);
  trd->natt_flags = natt_flags;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  trd->own_ifnum = (SshEngineIfnum) own_ifnum;
  trd->df_bit_processing = df_bit_processing;
  trd->packet_enlargement = (SshUInt8)packet_enlargement;

  qm->transform = trd->transform;

  /* Check IPsec SA. */
  if (trd->transform & SSH_PM_IPSEC_MANUAL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Can't import manual keyed IPsec SA"));
      error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      goto error;
    }
  if (trd->transform & SSH_PM_IPSEC_L2TP)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Can't import IPsec SA with L2tp transform"));
      error = SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH;
      goto error;
    }

  if (exported_import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_RULE_FORWARD)
    qm->forward = 1;

  if (exported_import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_TRANSPORT_MODE)
    {
      qm->transport_sent = 1;
      qm->transport_recv = 1;
    }

  memcpy(install->ike_spi_i, exported_ike_spi_i, exported_ike_spi_i_len);
  memcpy(install->ike_spi_r, exported_ike_spi_r, exported_ike_spi_r_len);

  if (exported_tunnel_app_id_len > 0)
    {
      install->tunnel_app_id = ssh_malloc(exported_tunnel_app_id_len);
      if (install->tunnel_app_id == NULL)
        {
          error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
          goto error;
        }
      memcpy(install->tunnel_app_id, exported_tunnel_app_id,
             exported_tunnel_app_id_len);
    }
  install->tunnel_app_id_len = exported_tunnel_app_id_len;

  if (exported_outer_tunnel_app_id_len > 0)
    {
      install->outer_tunnel_app_id =
        ssh_malloc(exported_outer_tunnel_app_id_len);
      if (install->outer_tunnel_app_id == NULL)
        {
          error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
          goto error;
        }
      memcpy(install->outer_tunnel_app_id, exported_outer_tunnel_app_id,
             exported_outer_tunnel_app_id_len);
    }
  install->outer_tunnel_app_id_len = exported_outer_tunnel_app_id_len;

  if (exported_rule_app_id_len > 0)
    {
      install->rule_app_id = ssh_malloc(exported_rule_app_id_len);
      if (install->rule_app_id == NULL)
        {
          error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
          goto error;
        }
      memcpy(install->rule_app_id, exported_rule_app_id,
             exported_rule_app_id_len);
    }
  install->rule_app_id_len = exported_rule_app_id_len;

  install->local_ike_id = local_id;
  install->remote_ike_id = remote_id;

  *qm_ret = qm;

  SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
  return error;

 decode_error:
  SSH_DEBUG(SSH_D_FAIL, ("IPsec SA decode failed"));
  error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;

 error:
  SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);

  if (qm)
    ssh_pm_qm_free(pm, qm);
  if (local_id)
    ssh_pm_ikev2_payload_id_free(local_id);
  if (remote_id)
    ssh_pm_ikev2_payload_id_free(remote_id);

  return error;
}


SshOperationHandle
ssh_pm_ipsec_sa_import(SshPm pm,
                       SshBuffer buffer,
                       SshPmIpsecSAPreImportCB import_callback,
                       void *import_callback_context,
                       SshPmIpsecSAImportStatusCB status_callback,
                       void *status_callback_context)
{
  SshPmImportIpsecInstall install = NULL;
  SshPmQm qm = NULL;
  SshPmSAImportStatus error = SSH_PM_SA_IMPORT_OK;
  SshTime now;

  /* The SA import-export API is designed for local SA storage and recovery
     after crash or suspend. This means that SA import does not need to
     consider SA rekeys or updates because the SAs are always imported in to
     an freshly initialized system without conflicting SAs.

     Support for redundant fail-over GW type of scenario would require atleast
     the following changes:

     * Import of IPsec SA rekeys: Rekeyed IPsec SAs must be installed as
       "rekeys", i.e. with `qm->rekey' set to 1. Some other minor changes maybe
       necessary.

     * Import of IPsec SA updates: New code needs to added for updating the
       peer object and the transforms. See ssh_pm_ipsec_sa_update().

     * Export of IPsec SA events: Encoding/decoding of the UPDATED, REKEYED
       and DELETED SA events needs to be added.
  */

  /* Check input parameters. */
  if (buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      error = SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
      goto fail;
    }

  /* Allocate installation context. */
  install = ssh_calloc(1, sizeof(*install));
  if (install == NULL)
    {
      error = SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY;
      goto fail;
    }
  install->done = FALSE;
  install->pm = pm;

  /* Decode exported IPsec SA. */
  error = pm_ipsec_sa_decode(pm, buffer, &qm, install);
  if (error != SSH_PM_SA_IMPORT_OK)
    goto fail;

  SSH_ASSERT(qm != NULL);

  /* Lookup p1 by IKE SPI. */
  qm->p1 = (SshPmP1) ssh_pm_ike_sa_get_by_spi(pm->sad_handle,
                                              install->ike_spi_i);
  if (qm->p1 == NULL)
    qm->p1 = (SshPmP1) ssh_pm_ike_sa_get_by_spi(pm->sad_handle,
                                                install->ike_spi_r);

  /* Check p1 usability for child SA import. */
  if (qm->p1 != NULL)
    {
      if (qm->p1->failed || qm->p1->unusable ||
          qm->p1->rekey_pending || !qm->p1->done)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("IKE SA %p unusable, cannot import IPsec SA %@",
                     qm->p1->ike_sa,
                     pm_ipsec_spi_render, qm));
          error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
          goto fail;
        }
    }
  else if ((qm->sa_handler_data.trd.control.control_flags
            & SSH_ENGINE_TR_C_IKEV1_SA) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No IKEv2 SA found, cannot import IPsec SA"));
      error = SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND;
      goto fail;
    }

  /* Calculate remaining transform lifetime from absolute expiry time. */
  if ((install->import_flags & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
      == 0)
    {
      now = ssh_time();
      if (install->expire_time <= now)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPsec SA has already expired"));
          error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;
          goto fail;
        }

      qm->trd_life_seconds = (SshUInt32)(install->expire_time - now);

      /* Handle possible host clock mismatch. */
      if (qm->trd_life_seconds > install->life_seconds)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Negotiated IPsec SA lifetime is smaller than expiry time "
                   "indicates, setting lifetime to %d seconds",
                   (unsigned long) install->life_seconds));
          qm->trd_life_seconds = install->life_seconds;
        }
    }

  /* Start installation */
  install->qm = qm;
  install->import_cb = import_callback;
  install->import_context = import_callback_context;
  install->status_cb = status_callback;
  install->status_context = status_callback_context;

  ssh_fsm_thread_init(&pm->fsm, &install->thread,
                      pm_st_ipsec_sa_import_start,
                      NULL_FNPTR,
                      pm_ipsec_sa_import_destructor,
                      install);

  SSH_ASSERT(error == SSH_PM_SA_IMPORT_OK);
  return NULL;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("IPSec SA import failed"));
  SSH_ASSERT(error != SSH_PM_SA_IMPORT_OK);

  if (qm)
    ssh_pm_qm_free(pm, qm);

  if (install)
    {
      /* If there is no IKE SA for an IPsec SA that is waiting
         for old SPI invalidation, then return error SA expired. */
      if ((install->import_flags
           & SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS)
          && error == SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND)
        error = SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED;

      pm_ipsec_sa_import_uninit_install(install);
      ssh_free(install);
    }

  if (status_callback != NULL_FNPTR)
    (*status_callback)(pm, error, NULL, status_callback_context);

  return NULL;
}


SshPmSAImportStatus
ssh_pm_ipsec_sa_decode_deleted_event(SshBuffer buffer,
                                     SshInetIPProtocolID *ipproto_ret,
                                     SshUInt32 *inbound_spi_ret,
                                     SshUInt32 *outbound_spi_ret)
{
  size_t offset;
  SshUInt32 version, type;
  unsigned int ipproto;
  SshUInt32 inbound_spi, outbound_spi;

  if (buffer == NULL
      || ipproto_ret == NULL
      || inbound_spi_ret == NULL
      || outbound_spi_ret == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_UINT32(&version),
                             SSH_DECODE_UINT32(&type),
                             SSH_FORMAT_END);
  if (offset == 0
      || version != SSH_PM_SA_EXPORT_VERSION
      || type != SSH_PM_SA_EXPORT_IPSEC_SA_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IPsec SA export header"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  offset = ssh_decode_buffer(buffer,
                             SSH_DECODE_CHAR(&ipproto),
                             SSH_DECODE_UINT32(&inbound_spi),
                             SSH_DECODE_UINT32(&outbound_spi),
                             SSH_FORMAT_END);
  if (offset == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPsec SA destroyed event decode failed"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  if ((ipproto != SSH_IPPROTO_ESP && ipproto != SSH_IPPROTO_AH)
      || inbound_spi == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Corrupted IPsec SA destroyed event"));
      return SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT;
    }

  *ipproto_ret = (SshInetIPProtocolID) ipproto;
  *inbound_spi_ret = inbound_spi;
  *outbound_spi_ret = outbound_spi;

  SSH_DEBUG(SSH_D_LOWOK, ("Decoded IPsec SA %@-%08lx destroyed event",
                          ssh_ipproto_render, (SshUInt32) ipproto,
                          (unsigned long) *inbound_spi_ret));

  return SSH_PM_SA_IMPORT_OK;
}


/*********************** IPsec SA update *************************************/

/** Update IKE SA to exported IPsec SA. The application should call this
    whenever it receives a SSH_PM_SA_EVENT_REKEYED event for an IKEv2 SA.
    This updates the exported IPsec SA in `buffer' to use the new IKEv2 SA
    identified by `ike_sa' event handle. */
size_t
ssh_pm_ipsec_sa_export_update_ike_sa(SshPm pm,
                                     SshBuffer buffer,
                                     SshPmIkeSAEventHandle ike_sa)
{
  SshPmImportIpsecInstallStruct install;
  SshPmQm qm = NULL;

  /* Check input parameters. */
  if (buffer == NULL || ike_sa == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      return 0;
    }

  if (ike_sa->event != SSH_PM_SA_EVENT_REKEYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid input IKE SA event handle"));
      return 0;
    }

  /* Import the IPsec SA to a 'qm' data structure. */
  memset(&install, 0, sizeof(install));
  if (pm_ipsec_sa_decode(pm, buffer, &qm, &install) != SSH_PM_SA_IMPORT_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to import IPsec SA"));
      return 0;
    }

  SSH_ASSERT(qm != NULL);
  SSH_PM_ASSERT_QM(qm);

  /* Check if the parent IKE SA of the Quick-Mode is the IKE SA
     which has just been rekeyed. If so, then update the IKE SA
     information of the Quick-Mode and then re-export it to 'buffer'.
     Otherwise leave the exported SA in 'buffer' unmodified. */
  if (memcmp(install.ike_spi_i, ike_sa->p1->old_ike_spi_i, 8) == 0 &&
      memcmp(install.ike_spi_r, ike_sa->p1->old_ike_spi_r, 8) == 0)
    {
      if (pm_ipsec_sa_import_prepare_qm(pm, qm, install.tunnel_id,
                                        install.rule_id)
          != SSH_PM_SA_IMPORT_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to prepare qm"));
          goto out;
        }

      SSH_DEBUG(SSH_D_LOWOK,
                ("Updating IKE SPI for IPsec SA %@ from %@ - %@ to %@ - %@",
                 pm_ipsec_spi_render, qm,
                 pm_ike_spi_render, install.ike_spi_i,
                 pm_ike_spi_render, install.ike_spi_r,
                 pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_i,
                 pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_r));

      SSH_DEBUG(SSH_D_MIDOK,
                ("Re-linearizing the IPsec SA %@ after parent IKE SA rekey",
                 pm_ipsec_spi_render, qm));
      ssh_buffer_clear(buffer);
      pm_ipsec_sa_encode(pm, qm,
                         ike_sa->p1->local_id,
                         ike_sa->p1->remote_id,
                         ike_sa->p1->ike_sa->ike_spi_i,
                         ike_sa->p1->ike_sa->ike_spi_r,
                         buffer, install.expire_time,
                         install.import_flags);
    }
  else
    SSH_DEBUG(SSH_D_LOWOK,
              ("Ignoring update of IPsec SA %@ that was not negotiated with "
               "IKE SA %@ - %@",
               pm_ipsec_spi_render, qm,
               pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_i,
               pm_ike_spi_render, ike_sa->p1->ike_sa->ike_spi_r));

 out:
  ssh_pm_qm_free(pm, qm);
  pm_ipsec_sa_import_uninit_install(&install);
  return ssh_buffer_len(buffer);
}

/** Internal utility function for matching IPsec SAs and IPsec SA events. */
static Boolean
pm_ipsec_sa_update_match_event(SshPm pm,
                               SshPmQm qm,
                               SshPmIPsecSAEventHandle ipsec_sa)
{
  SshInetIPProtocolID event_ipproto;
  SshUInt32 event_outbound_spi, event_inbound_spi;
  SshInetIPProtocolID sa_ipproto;
  SshUInt32 sa_outbound_spi, sa_inbound_spi;
  SshEngineTransformData trd;

  SSH_PM_ASSERT_QM(qm);
  SSH_ASSERT(ipsec_sa != NULL);

  /* Extract protocol and SPI values from event handle. */
  event_ipproto = ssh_pm_ipsec_sa_get_protocol(pm, ipsec_sa);
  event_outbound_spi = ssh_pm_ipsec_sa_get_outbound_spi(pm, ipsec_sa);
  event_inbound_spi = ssh_pm_ipsec_sa_get_inbound_spi(pm, ipsec_sa);

  /* Extract protocol and SPI values from SA. */
  trd = &qm->sa_handler_data.trd.data;
  if (qm->transform & SSH_PM_IPSEC_ESP)
    {
      sa_ipproto = SSH_IPPROTO_ESP;
      sa_outbound_spi = trd->spis[SSH_PME_SPI_ESP_OUT];
      sa_inbound_spi = trd->spis[SSH_PME_SPI_ESP_IN];
    }
  else if (qm->transform & SSH_PM_IPSEC_AH)
    {
      sa_ipproto = SSH_IPPROTO_AH;
      sa_outbound_spi = trd->spis[SSH_PME_SPI_AH_OUT];
      sa_inbound_spi = trd->spis[SSH_PME_SPI_AH_IN];
    }
  else
    return FALSE;

  /* Compare */
  if (event_ipproto != sa_ipproto
      || event_outbound_spi != sa_outbound_spi
      || event_inbound_spi != sa_inbound_spi)
    return FALSE;

  return TRUE;
}


/** Update exported IPsec SA. The application should call this whenever it
    receives a SSH_PM_SA_EVENT_UPDATED for an IPsec SA. This updates the
    IPsec SA in `buffer' according to the changes in `ipsec_sa' event handle.
*/
size_t
ssh_pm_ipsec_sa_export_update(SshPm pm,
                              SshBuffer buffer,
                              SshPmIPsecSAEventHandle ipsec_sa)
{
  SshPmQm qm = NULL;
  SshPmImportIpsecInstallStruct install;
  SshEngineTransformData trd;
#ifdef SSH_IPSEC_TCPENCAP
  SshEngineTransformControl trc;
#endif /* SSH_IPSEC_TCPENCAP */

  memset(&install, 0, sizeof(install));

  if (ipsec_sa == NULL || buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid arguments"));
      goto fail;
    }

  if (ipsec_sa->event != SSH_PM_SA_EVENT_UPDATED)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Ignoring IPsec SA event (not SSH_PM_SA_EVENT_UPDATED)"));
      return ssh_buffer_len(buffer);
    }

  /* Import the IPsec SA to a 'qm' data structure. */
  if (pm_ipsec_sa_decode(pm, buffer, &qm, &install) != SSH_PM_SA_IMPORT_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to decode exported IPsec SA"));
      goto fail;
    }

  SSH_ASSERT(qm != NULL);
  SSH_PM_ASSERT_QM(qm);

  /* Check that the IPsec SA event matches the imported IPsec SA. */
  if (pm_ipsec_sa_update_match_event(pm, qm, ipsec_sa))
    {
      if (pm_ipsec_sa_import_prepare_qm(pm, qm, install.tunnel_id,
                                        install.rule_id)
          != SSH_PM_SA_IMPORT_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to prepare qm"));
          goto fail;
        }

      /* Update qm. */
      if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
          trd = &qm->sa_handler_data.trd.data;
          trd->own_addr = *ipsec_sa->peer->local_ip;
          trd->local_port = ipsec_sa->peer->local_port;
          trd->gw_addr = *ipsec_sa->peer->remote_ip;
          trd->remote_port = ipsec_sa->peer->remote_port;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          if (ipsec_sa->enable_natt)
            trd->transform |= SSH_PM_IPSEC_NATT;
          else
            trd->transform &= ~SSH_PM_IPSEC_NATT;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_TCPENCAP
          trc = &qm->sa_handler_data.trd.control;
          if (ipsec_sa->enable_tcpencap)
            memcpy(trc->tcp_encaps_conn_spi, ipsec_sa->tcp_encaps_conn_spi, 8);
          else
            memset(trc->tcp_encaps_conn_spi, 0, 8);
#endif /* SSH_IPSEC_TCPENCAP */

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Updating IPsec SA %@ to use addresses local %@:%d "
                     "remote %@:%d",
                     pm_ipsec_spi_render, qm,
                     ssh_ipaddr_render, &trd->own_addr, trd->local_port,
                     ssh_ipaddr_render, &trd->gw_addr, trd->remote_port));
        }

      else if (ipsec_sa->update_type
               == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        {
          install.import_flags
            |= SSH_PM_IPSEC_SA_IMPORT_FLAG_INVALIDATE_OLD_SPIS;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Marking IPsec SA %@ as waiting for old SPI invalidation",
                     pm_ipsec_spi_render, qm));
        }

      SSH_DEBUG(SSH_D_MIDOK,
                ("Re-linearizing the updated IPsec SA %@",
                 pm_ipsec_spi_render, qm));

      /* Clear export buffer. */
      ssh_buffer_clear(buffer);

      /* Re-export updated IPsec SA. */
      pm_ipsec_sa_encode(pm, qm,
                         install.local_ike_id,
                         install.remote_ike_id,
                         install.ike_spi_i,
                         install.ike_spi_r,
                         buffer,
                         install.expire_time,
                         install.import_flags);
    }
  else
    SSH_DEBUG(SSH_D_LOWOK, ("Ignoring update event for IPsec SA %@",
                            pm_ipsec_spi_render, qm));

  ssh_pm_qm_free(pm, qm);
  pm_ipsec_sa_import_uninit_install(&install);

  return ssh_buffer_len(buffer);

  /* Error handling. */
 fail:
  if (qm != NULL)
    ssh_pm_qm_free(pm, qm);

  pm_ipsec_sa_import_uninit_install(&install);

  return 0;
}

#endif /* SSHDIST_IPSEC_SA_EXPORT */
