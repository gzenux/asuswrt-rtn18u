/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 conf attr. type table and print function.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringAttributeType"

/* Conf attribute type to string mapping.  */
const SshKeywordStruct ssh_ikev2_attr_type_to_string_table[] = {
  { "IPv4 address", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS },
  { "IPv4 netmask", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK },
  { "IPv4 dns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS },
  { "IPv4 nbns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS },
  { "address expiry", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY },
  { "IPv4 dhcp", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP },
  { "application version", SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION },
  { "IPv6 address", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS },
  { "IPv6 dns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS },
  { "IPv6 nbns", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS },
  { "IPv6 dhcp", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP },
  { "IPv4 subnet", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET },
  { "supported attributes", SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES },
  { "IPv6 subnet", SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET },
  { "Banner", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BANNER },
  { "save password", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SAVE_PASSWD },
  { "default domain", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DEFAULT_DOMAIN },
  { "Split DNS name", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_DNS_NAME },
  { "Split network include",
    SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_SPLIT_NET_INCLUDE },
  { "NAT-T port", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_NATT_PORT },
  { "Local LAN", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_LOCAL_LAN },
  { "PFS", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_PFS },
  { "FW type", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_FW_TYPE },
  { "Backup servers", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_BACKUP_SERVERS },
  { "DDNS hostname", SSH_IKEV2_CFG_ATTRIBUTE_CISCO_UNITY_DDNS_HOSTNAME },
  { NULL, 0 }
};

const char *ssh_ikev2_attr_to_string(SshIkev2ConfAttributeType attr_type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_attr_type_to_string_table,
                               attr_type);
  if (name == NULL)
    return "unknown";
  return name;
}
