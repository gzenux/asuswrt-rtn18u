/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversion routines of IKE CFG payloads between IKEv1 and IKEv2.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-payloads.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "isakmp_doi.h"
#include "isakmp_util.h"

#include "ikev2-fb.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackCfgConv"

#ifdef SSHDIST_ISAKMP_CFG_MODE
SshIkev2PayloadConf
ikev2_fb_cfgv1_to_cfgv2(SshSADHandle sad_handle, SshIkePayloadAttr attrs)
{
  SshIkev2Error err;
  SshIkev2PayloadConf conf = NULL;
  Boolean ipv6_address_seen, ipv6_netmask_seen;
  unsigned char buf[17];
  int i;

  /* This routine will fail if the IKEv1 attributes contain more than one
     IPv6 address or more than one IPv6 netmask. */
  ipv6_address_seen = ipv6_netmask_seen = FALSE;

  if (attrs == NULL)
    return NULL;

  /* This function expects that equality of IKEv1 and IKEv2 config
     attribute types persists. */
  if ((conf
       = ssh_ikev2_conf_allocate(sad_handle, (SshIkev2ConfType)attrs->type))
      != NULL)
    {
      for (i = 0; i < attrs->number_of_attributes; i++)
        {
          if (attrs->attributes[i].attribute_type ==
              SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NETMASK)
            {
              unsigned char byte, netmask = 0;
              int j, bits, shift;

              if (ipv6_netmask_seen)
                goto error;

              if (attrs->attributes[i].attribute_length == 16)
                {
                  for (j = 0; j < 16; j++)
                    {
                      if (attrs->attributes[i].attribute[j] != 0xff)
                        {
                          byte = attrs->attributes[i].attribute[j];
                          bits = 0;
                          shift = 7;
                          /* Count the number of most significant 1 bits
                             in 'byte'. */
                          while ((byte >> shift) & 0x1)
                            bits++, shift--;

                          netmask += bits;
                          break;
                        }
                      netmask += 8;
                    }

                  buf[16] = netmask;
                  ipv6_netmask_seen = TRUE;
                }
            }
          else if (attrs->attributes[i].attribute_type ==
                   SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS)
            {
              if (ipv6_address_seen)
                goto error;

              if (attrs->attributes[i].attribute_length == 0)
                {
                  err = ssh_ikev2_conf_add(
                                  conf,
                                  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS,
                                  0, NULL);
                  if (err != SSH_IKEV2_ERROR_OK)
                    goto error;
                }
              else if (attrs->attributes[i].attribute_length == 16)
                {
                  memcpy(buf, attrs->attributes[i].attribute, 16);
                  ipv6_address_seen = TRUE;
                }
            }
          else
            {
              err = ssh_ikev2_conf_add(conf,
                                       (SshIkev2ConfAttributeType)attrs
                                       ->attributes[i].attribute_type,
                                       attrs->attributes[i].attribute_length,
                                       attrs->attributes[i].attribute);
              if (err != SSH_IKEV2_ERROR_OK)
                goto error;
            }
        }

      if (ipv6_address_seen && ipv6_netmask_seen)
        {
          err = ssh_ikev2_conf_add(
                  conf,
                  SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS,
                  17, buf);

          if (err != SSH_IKEV2_ERROR_OK)
            goto error;
        }
    }

  ssh_ikev2_payload_conf_debug(SSH_D_LOWOK,
                               "Converted IKEv1 conf payload to IKEv2 "
                               "payload",
                               "V1_TO_V2",
                               conf);

  return conf;

 error:
  if (conf != NULL)
    ssh_ikev2_conf_free(sad_handle, conf);
  return NULL;
}


SshIkePayloadAttr
ikev2_fb_cfgv2_to_cfgv1(SshSADHandle sad_handle, SshIkev2PayloadConf conf)
{
  SshIkePayloadAttr attr;
  int i;
  SshIkeSAAttributeList list;

  ssh_ikev2_payload_conf_debug(SSH_D_LOWOK,
                               "Converting IKEv2 conf payload to IKEv1 "
                               "format",
                               "V2_TO_V1",
                               conf);

  if (conf == NULL)
    return NULL;

  if ((attr = ssh_calloc(1, sizeof(*attr))) == NULL)
    return NULL;

  if ((list = ssh_ike_data_attribute_list_allocate()) == NULL)
    {
      ssh_free(attr);
      return NULL;
    }

  for (i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      /* Special handling for IPv6 addresses. */
      if (conf->conf_attributes[i].attribute_type ==
          SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS)
        {
          if (conf->conf_attributes[i].length == 0)
            {
              ssh_ike_data_attribute_list_add(
                                       list,
                                       SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS,
                                       NULL, 0);
            }
          else if (conf->conf_attributes[i].length == 17)
            {
              SshIpAddrStruct mask, mask2;
              unsigned char buf[16];
              size_t len;

              SSH_VERIFY(ssh_ipaddr_parse(&mask2, "0:0:0:0:0:0:0:0"));
              ssh_ipaddr_set_bits(&mask2, &mask2, 0, 1);
              ssh_ipaddr_set_bits(&mask, &mask2,
                                  conf->conf_attributes[i].value[16], 0);

              memset(buf, 0, sizeof(buf));
              SSH_IP_ENCODE(&mask, buf, len);

              ssh_ike_data_attribute_list_add(
                                       list,
                                       SSH_IKE_CFG_ATTR_INTERNAL_IPV6_ADDRESS,
                                       conf->conf_attributes[i].value,
                                       16);

              ssh_ike_data_attribute_list_add(
                                       list,
                                       SSH_IKE_CFG_ATTR_INTERNAL_IPV6_NETMASK,
                                       buf,
                                       len);
            }
        }
      else
        {
          ssh_ike_data_attribute_list_add(
                                       list,
                                       conf->conf_attributes[i].attribute_type,
                                       conf->conf_attributes[i].value,
                                       conf->conf_attributes[i].length);
        }
    }

  attr->type = (int) conf->conf_type;
  attr->number_of_attributes = 0;
  attr->attributes =
    ssh_ike_data_attribute_list_get(list,
                                    &attr->number_of_attributes);

  ssh_ike_data_attribute_list_free(list);

  return attr;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IKEV1 */
