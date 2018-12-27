/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 ID type table and print function.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringId"

/* ID type to string mapping.  */
const SshKeywordStruct ssh_ikev2_id_to_string_table[] = {
  { "ipv4", SSH_IKEV2_ID_TYPE_IPV4_ADDR },
  { "fqdn", SSH_IKEV2_ID_TYPE_FQDN },
  { "email", SSH_IKEV2_ID_TYPE_RFC822_ADDR },
  { "ipv6", SSH_IKEV2_ID_TYPE_IPV6_ADDR },
  { "dn", SSH_IKEV2_ID_TYPE_ASN1_DN },
  { "gn", SSH_IKEV2_ID_TYPE_ASN1_GN },
  { "keyid", SSH_IKEV2_ID_TYPE_KEY_ID },
  { NULL, 0 }
};

const char *ssh_ikev2_id_to_string(SshIkev2IDType id_type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_id_to_string_table, id_type);
  if (name == NULL)
    return "unknown";
  return name;
}
