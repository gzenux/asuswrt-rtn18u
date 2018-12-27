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

#define SSH_DEBUG_MODULE "SshIkev2StringAuthMethod"

/* Auth method to string mapping.  */
const SshKeywordStruct ssh_ikev2_auth_method_to_string_table[] = {
  { "RSA Sig", SSH_IKEV2_AUTH_METHOD_RSA_SIG },
  { "DSA Sig", SSH_IKEV2_AUTH_METHOD_DSS_SIG },
  { "Shared key", SSH_IKEV2_AUTH_METHOD_SHARED_KEY },
#ifdef SSHDIST_CRYPT_ECP
  { "ECDSA Sig with SHA-256", SSH_IKEV2_AUTH_METHOD_ECP_DSA_256 },
  { "ECDSA Sig with SHA-384", SSH_IKEV2_AUTH_METHOD_ECP_DSA_384 },
  { "ECDSA Sig with SHA-512", SSH_IKEV2_AUTH_METHOD_ECP_DSA_521 },
#endif /* SSHDIST_CRYPT_ECP */
  { NULL, 0 }
};

const char *ssh_ikev2_auth_method_to_string(SshIkev2AuthMethod auth_method)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_auth_method_to_string_table,
                               auth_method);
  if (name == NULL)
    return "unknown";
  return name;
}
