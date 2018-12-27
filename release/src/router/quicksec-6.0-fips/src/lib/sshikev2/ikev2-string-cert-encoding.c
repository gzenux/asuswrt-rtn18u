/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 CERT Encoding type table and print function.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringCertEncoding"

#ifdef SSHDIST_IKE_CERT_AUTH

/* Cert encoding to string mapping.  */
const SshKeywordStruct ssh_ikev2_cert_encoding_to_string_table[] = {
  { "PKCS7", SSH_IKEV2_CERT_PKCS7_WRAPPED_X_509 },
  { "PGP", SSH_IKEV2_CERT_PGP },
  { "DNS", SSH_IKEV2_CERT_DNS_SIGNED_KEY },
  { "X509", SSH_IKEV2_CERT_X_509 },
  { "Kerberos", SSH_IKEV2_CERT_KERBEROS_TOKEN },
  { "CRL", SSH_IKEV2_CERT_CRL },
  { "ARL", SSH_IKEV2_CERT_ARL },
  { "SPKI", SSH_IKEV2_CERT_SPKI },
  { "X509 Attr", SSH_IKEV2_CERT_X_509_ATTRIBUTE },
  { "RAW RSA", SSH_IKEV2_CERT_RAW_RSA_KEY },
  { "HASH & URL X509", SSH_IKEV2_CERT_HASH_AND_URL_X509 },
  { "HASH & URL X509 BUNDLE", SSH_IKEV2_CERT_HASH_AND_URL_X509_BUNDLE },
  { NULL, 0 }
};

const char *ssh_ikev2_cert_encoding_to_string(SshIkev2CertEncoding cert_type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_cert_encoding_to_string_table,
                               cert_type);
  if (name == NULL)
    return "unknown";
  return name;
}

#endif /* SSHDIST_IKE_CERT_AUTH */
