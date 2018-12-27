/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Payload Render routines.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshmiscstring.h"

#define SSH_DEBUG_MODULE "SshIkev2RenderPayload"


int ssh_ikev2_payload_ke_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  SshIkev2PayloadKE ke = datum;
  int len;

  if (ke == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len =
    ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                 "KE(group = %s (%d), len = %zd, data = %.*@)",
                 ssh_ikev2_transform_to_string(SSH_IKEV2_TRANSFORM_TYPE_D_H,
                                               ke->dh_group),
                 (int) ke->dh_group, ke->key_exchange_len,
                 ke->key_exchange_len, ssh_hex_render,
                 ke->key_exchange_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

int ssh_ikev2_payload_id_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  SshIkev2PayloadID id = datum;
  int len;

  if (id == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "ID%s(type = %s (%d), len = %d, value = ",
                     (precision == 1 ? "i" :
                      (precision == 2 ? "r" : "")),
                     ssh_ikev2_id_to_string(id->id_type),
                     id->id_type,
                     id->id_data_size);
  if (len >= buf_size)
    return buf_size + 1;

  /* Print data. */
  if (id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR)
    len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%@)",
                        ssh_ipaddr4_uint32_render,
                        (void *) (size_t) SSH_GET_32BIT(id->id_data));
  else if (id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
    len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%@)",
                        ssh_ipaddr6_byte16_render,
                        id->id_data);
  else if (id->id_type == SSH_IKEV2_ID_TYPE_ASN1_DN ||
           id->id_type == SSH_IKEV2_ID_TYPE_ASN1_GN ||
           id->id_type == SSH_IKEV2_ID_TYPE_KEY_ID)
    len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%.*@)",
                        id->id_data_size,
                        ssh_hex_render,
                        id->id_data);
  else
    len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "%.*@)",
                        id->id_data_size,
                        ssh_safe_text_render,
                        id->id_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


#ifdef SSHDIST_IKE_CERT_AUTH
int ssh_ikev2_payload_cert_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  SshIkev2PayloadCert cert = datum;
  int len;

  if (cert == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "CERT(encoding = %s (%d), len = %d, data = %.*@)",
                     ssh_ikev2_cert_encoding_to_string(cert->cert_encoding),
                     cert->cert_encoding,
                     cert->cert_size,
                     cert->cert_size, ssh_hex_render,
                     cert->cert_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_certreq_render(unsigned char *buf, int buf_size,
                                     int precision, void *datum)
{
  SshIkev2PayloadCertReq certreq = datum;
  int len;

  if (certreq == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "CERTREQ(encoding = %s (%d), len = %d, data = %.*@)",
                     ssh_ikev2_cert_encoding_to_string(certreq->cert_encoding),
                     certreq->cert_encoding,
                     certreq->authority_size,
                     certreq->authority_size, ssh_hex_render,
                     certreq->authority_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


int ssh_ikev2_payload_auth_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  SshIkev2PayloadAuth auth = datum;
  int len;

  if (auth == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "AUTH(method = %s (%d), len = %d, data = %.*@)",
                     ssh_ikev2_auth_method_to_string(auth->auth_method),
                     auth->auth_method,
                     auth->authentication_size,
                     auth->authentication_size, ssh_hex_render,
                     auth->authentication_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_nonce_render(unsigned char *buf, int buf_size,
                                   int precision, void *datum)
{
  SshIkev2PayloadNonce nonce = datum;
  int len;

  if (nonce == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "NONCE(len = %d, data = %.*@)",
                     nonce->nonce_size,
                     nonce->nonce_size, ssh_hex_render,
                     nonce->nonce_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_notify_render(unsigned char *buf, int buf_size,
                                    int precision, void *datum)
{
  SshIkev2PayloadNotify notify = datum;
  int len;

  if (notify == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "N(type = %s (%d), protocol = %s (%d), spi_len = %d, "
                     "spi = %.*@, data_len = %d data = %.*@)",
                     ssh_ikev2_notify_to_string(notify->notify_message_type),
                     notify->notify_message_type,
                     ssh_ikev2_protocol_to_string(notify->protocol),
                     notify->protocol,
                     notify->spi_size,
                     notify->spi_size, ssh_hex_render, notify->spi_data,
                     notify->notification_size,
                     notify->notification_size, ssh_hex_render,
                     notify->notification_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_delete_render(unsigned char *buf, int buf_size,
                                    int precision, void *datum)
{
  SshIkev2PayloadDelete d = datum;
  int len;

  if (d == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  if (d->spi_size == 4)
    len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                       "DELETE(protocol = %s (%d), number of spis = %d, "
                       "spi_size = %d, spis = %.*@)",
                       ssh_ikev2_protocol_to_string(d->protocol),
                       d->protocol,
                       d->number_of_spis,
                       d->spi_size,
                       -d->number_of_spis,
                       ssh_uint32_array_render, d->spi.spi_array);
  else
    len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                       "DELETE(protocol = %s (%d), number of spis = %d, "
                       "spi_size = %d, spis = %.*@)",
                       ssh_ikev2_protocol_to_string(d->protocol),
                       d->protocol,
                       d->number_of_spis,
                       d->spi_size,
                       d->number_of_spis * d->spi_size,
                       ssh_hex_render, d->spi.spi_table);

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_vid_render(unsigned char *buf, int buf_size,
                                 int precision, void *datum)
{
  SshIkev2PayloadVendorID vid = datum;
  int len;

  if (vid == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "VID(len = %d, data = %.*@)",
                     vid->vendorid_size,
                     vid->vendorid_size, ssh_hex_render,
                     vid->vendorid_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


#ifdef SSHDIST_IKE_EAP_AUTH
int ssh_ikev2_payload_eap_render(unsigned char *buf, int buf_size,
                                 int precision, void *datum)
{
  SshIkev2PayloadEap eap = datum;
  int len;

  if (eap == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "EAP(len = %d, data = %.*@)",
                     eap->eap_size,
                     eap->eap_size, ssh_hex_render,
                     eap->eap_data);
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}
#endif /* SSHDIST_IKE_EAP_AUTH */


int ssh_ikev2_payload_ts_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  SshIkev2PayloadTS ts = datum;
  int len;
  int i;

  if (ts == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "TS%s(# ts = %d, ",
                     (precision == 1 ? "i" :
                      (precision == 2 ? "r" : "")),
                     (int) ts->number_of_items_used);
  if (len >= buf_size)
    return buf_size + 1;

  for(i = 0; i < ts->number_of_items_used; i++)
    {
      /* Print TS. */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          "[%d] type = %s (%d), protocol = %d, ",
                          i,
                          ts->items[i].ts_type ==
                          SSH_IKEV2_TS_IPV4_ADDR_RANGE ?
                          "ipv4 range" :
                          (ts->items[i].ts_type ==
                           SSH_IKEV2_TS_IPV6_ADDR_RANGE ?
                           "ipv6 range" : "unknown"),
                          ts->items[i].ts_type,
                          ts->items[i].proto);
      if (len >= buf_size)
        return buf_size + 1;

      if (ts->items[i].start_port == 0 &&
          ts->items[i].end_port == 65535)
        len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
"port = any");
      else if (ts->items[i].start_port == 65535 &&
               ts->items[i].end_port == 0)
        len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                            "port = opaque");
      else
        len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                            "port = %d - %d",
                            ts->items[i].start_port,
                            ts->items[i].end_port);
      if (len >= buf_size)
        return buf_size + 1;

      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          ", ip range = %@ - %@; ",
                          ssh_ipaddr_render, ts->items[i].start_address,
                          ssh_ipaddr_render, ts->items[i].end_address);
      if (len >= buf_size)
        return buf_size + 1;
    }
  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ")");
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


int ssh_ikev2_payload_conf_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  SshIkev2PayloadConf conf = datum;
  int len;
  int i;
  int p;

  if (conf == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1,
                     "CONF(type = %d, ",
                     conf->conf_type);
  if (len >= buf_size)
    return buf_size + 1;

  for(i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      /* Print attribute */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          "[%d] type = %s (%d), len = %d, ",
                          i,
                          ssh_ikev2_attr_to_string(conf->conf_attributes[i].
                                                   attribute_type),
                          conf->conf_attributes[i].attribute_type,
                          conf->conf_attributes[i].length);
      if (len >= buf_size)
        return buf_size + 1;

      if (conf->conf_attributes[i].length == 0)
        {
          len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                              "no value");
        }
      else
        {
          switch (conf->conf_attributes[i].attribute_type)
            {
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP:
              if (conf->conf_attributes[i].length == 4)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "value = %@",
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value));
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "error");
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET:
              if (conf->conf_attributes[i].length == 8)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "value = %@/%@",
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value),
                                    ssh_ipaddr4_uint32_render,
                                    (void *) (size_t)
                                    SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value + 4));
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "error");
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET:
              if (conf->conf_attributes[i].length == 17)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "value = %@/%d",
                                    ssh_ipaddr6_byte16_render,
                                    conf->conf_attributes[i].value,
                                    SSH_GET_8BIT(conf->conf_attributes[i].
                                                 value + 16));
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "error");
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS:
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP:
              if (conf->conf_attributes[i].length == 16)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "value = %@",
                                    ssh_ipaddr6_byte16_render,
                                    conf->conf_attributes[i].value);
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "error");
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY:
              if (conf->conf_attributes[i].length == 4)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "value = %ld",
                                    (long)
                                    SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value));
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    "error");
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BANNER:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DEFAULT_DOMAIN:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_DNS_NAME:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_FW_TYPE:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BACKUP_SERVERS:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DDNS_HOSTNAME:
            case SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION:
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "value = %.*@",
                                  conf->conf_attributes[i].length,
                                  ssh_safe_text_render,
                                  conf->conf_attributes[i].value);
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_LOCAL_LAN:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_NET_INCLUDE:
              for (p = 0; p < conf->conf_attributes[i].length; p = p + 14)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  " value = %@/%@",
                                  ssh_ipaddr4_uint32_render,
                                  (void *) (size_t)
                                  SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value + p),
                                  ssh_ipaddr4_uint32_render,
                                  (void *) (size_t)
                                  SSH_GET_32BIT(conf->conf_attributes[i].
                                                  value + p + 4));
              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SAVE_PASSWD:
            case SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_NATT_PORT:
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "value = %u",
                                  ((SshUInt16 *)
                                    conf->conf_attributes[i].value)[0]);

              break;
            case SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES:
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "value = %.*@",
                                  conf->conf_attributes[i].length,
                                  ssh_hex_render,
                                  conf->conf_attributes[i].value);
              break;
            default:
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "unknown value type");
              break;
            }
        }
      if (len >= buf_size)
        return buf_size + 1;
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "; ");
      if (len >= buf_size)
        return buf_size + 1;
    }
  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ")");
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

int ssh_ikev2_payload_sa_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  SshIkev2PayloadSA sa = datum;
  int prop, trans;
  int len;

  if (sa == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = ssh_snprintf(ssh_sstr(buf), buf_size + 1, "SA(");
  if (len >= buf_size)
    return buf_size + 1;

  for(prop = 0; prop < SSH_IKEV2_SA_MAX_PROPOSALS; prop++)
    {
      if (sa->protocol_id[prop] == 0)
        continue;
      /* Print proposal */
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          "[%d]", prop);
      if (sa->proposal_number != 0)
        {
          len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                              "(id = %d)", sa->proposal_number);
        }
      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                          " protocol = %s (%d), ",
                          ssh_ikev2_protocol_to_string(sa->protocol_id[prop]),
                          sa->protocol_id[prop]);
      if (len >= buf_size)
        return buf_size + 1;

      if (precision < 0)
        {
          if (sa->protocol_id[prop] == SSH_IKEV2_PROTOCOL_ID_AH ||
              sa->protocol_id[prop] == SSH_IKEV2_PROTOCOL_ID_ESP)
            {
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "spi_len = 4, spi = 0x%08lx, ",
                                  (unsigned long) sa->spis.ipsec_spis[prop]);
              if (len >= buf_size)
                return buf_size + 1;
            }
          else if (sa->protocol_id[prop] == SSH_IKEV2_PROTOCOL_ID_IKE &&
                   sa->spi_len == 8)
            {
              len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                  "spi_len = 8, spi = 0x%08lx %08lx, ",
                                  SSH_GET_32BIT(sa->spis.ike_spi),
                                  SSH_GET_32BIT(sa->spis.ike_spi + 4));
              if (len >= buf_size)
                return buf_size + 1;
            }
        }

      for(trans = 0; trans < sa->number_of_transforms[prop]; trans++)
        {
          len +=
            ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                         "%s",
                         ssh_ikev2_transform_to_string(sa->proposals[prop]
                                                       [trans].type,
                                                       sa->proposals[prop]
                                                       [trans].id));
          if (len >= buf_size)
            return buf_size + 1;

          if (sa->proposals[prop][trans].transform_attribute != 0)
            {
              if ((sa->proposals[prop][trans].transform_attribute & 0xffff0000)
                  == 0x800e0000)
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    " key len = %d",
                                    (int) (sa->proposals[prop][trans].
                                           transform_attribute & 0xffff));
              else
                len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1,
                                    " attribute %d, value %d",
                                    (int) ((sa->proposals[prop][trans].
                                            transform_attribute >> 16)
                                           & 0x7fff),
                                    (int) (sa->proposals[prop][trans].
                                           transform_attribute & 0xffff));
              if (len >= buf_size)
                return buf_size + 1;
            }
          if (trans != sa->number_of_transforms[prop] - 1)
            len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ", ");
          if (len >= buf_size)
            return buf_size + 1;
        }

      if (len >= buf_size)
        return buf_size + 1;

      len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, "; ");
      if (len >= buf_size)
        return buf_size + 1;
    }
  len += ssh_snprintf(ssh_sstr(buf) + len, buf_size - len + 1, ")");
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}
