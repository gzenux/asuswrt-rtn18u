/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Auth method type table and print function.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringProtocol"

/* Protocol number to string mapping.  */
const SshKeywordStruct ssh_ikev2_protocol_to_string_table[] = {
  { "None", SSH_IKEV2_PROTOCOL_ID_NONE },
  { "IKE", SSH_IKEV2_PROTOCOL_ID_IKE },
  { "AH", SSH_IKEV2_PROTOCOL_ID_AH },
  { "ESP", SSH_IKEV2_PROTOCOL_ID_ESP },
  { NULL, 0 }
};

const char *ssh_ikev2_protocol_to_string(SshIkev2ProtocolIdentifiers protocol)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_protocol_to_string_table,
                               protocol);
  if (name == NULL)
    return "unknown";
  return name;
}
