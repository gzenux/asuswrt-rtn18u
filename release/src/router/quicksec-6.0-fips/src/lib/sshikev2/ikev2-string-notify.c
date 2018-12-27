/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Notify and error code tables and print functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringAuthMethod"

/* Notify number to string mapping.  */
const SshKeywordStruct ssh_ikev2_notify_to_string_table[] = {
  { "Reserved", SSH_IKEV2_NOTIFY_RESERVED },
  { "Unsupported critical payload",
    SSH_IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD },
  { "Invalid ike SPI", SSH_IKEV2_NOTIFY_INVALID_IKE_SPI },
  { "Invalid major version", SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION },
  { "Invalid syntax", SSH_IKEV2_NOTIFY_INVALID_SYNTAX },
  { "Invalid message ID", SSH_IKEV2_NOTIFY_INVALID_MESSAGE_ID },
  { "Invalid spi", SSH_IKEV2_NOTIFY_INVALID_SPI },
  { "No proposal chosen", SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN },
  { "Invalid KE payload", SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD },
  { "Authentication failed", SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED },
  { "Single pair required", SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED },
  { "No additional SAs", SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS },
  { "Internal address failure", SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE },
  { "Failed CP required", SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED },
  { "TS unacceptable", SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE },
  { "Invalid selectors", SSH_IKEV2_NOTIFY_INVALID_SELECTORS },
  { "Unacceptable address", SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS },
  { "Unexpected NAT detected", SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED },
  { "Temporary failure", SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE },
  { "Child SA not found", SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND },
  { "Initial contact", SSH_IKEV2_NOTIFY_INITIAL_CONTACT },
  { "Set window size", SSH_IKEV2_NOTIFY_SET_WINDOW_SIZE },
  { "Additional TS possible", SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE },
  { "IPCOMP supported", SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED },
  { "NAT detection source IP", SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP },
  { "NAT detection destination IP",
    SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP },
  { "Cookie", SSH_IKEV2_NOTIFY_COOKIE },
  { "Use transport mode", SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE },
  { "HTTP cert lookup supported",
    SSH_IKEV2_NOTIFY_HTTP_CERT_LOOKUP_SUPPORTED },
  { "Rekey SA", SSH_IKEV2_NOTIFY_REKEY_SA },
  { "ESP TFC padding not supported",
    SSH_IKEV2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED },
  { "Non first fragments also", SSH_IKEV2_NOTIFY_NON_FIRST_FRAGMENTS_ALSO },
  { "MOBIKE supported ", SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED },
  { "Additional IPv4 addresses", SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS },
  { "Additional IPv6 addresses", SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS },
  { "No additional addresses", SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES },
  { "Update Address", SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES },
  { "Cookie2", SSH_IKEV2_NOTIFY_COOKIE2 },
  { "No NAT's allowed", SSH_IKEV2_NOTIFY_NO_NATS_ALLOWED },
  { "Multiple auth supported", SSH_IKEV2_NOTIFY_MULTIPLE_AUTH_SUPPORTED },
  { "Another auth follows", SSH_IKEV2_NOTIFY_ANOTHER_AUTH_FOLLOWS },
  { "EAP only authentication", SSH_IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION},
  { "Fragmentation supported", SSH_IKEV2_NOTIFY_FRAGMENTATION_SUPPORTED },
  { NULL, 0 }
};

/* Error code to string mapping.  */
const SshKeywordStruct ssh_ikev2_error_to_string_table[] = {

  { "Error ok", SSH_IKEV2_ERROR_OK },
  { "Out of memory", SSH_IKEV2_ERROR_OUT_OF_MEMORY },
  { "Invalid argument", SSH_IKEV2_ERROR_INVALID_ARGUMENT },
  { "Crypto operation failed", SSH_IKEV2_ERROR_CRYPTO_FAIL },
  { "Timed out", SSH_IKEV2_ERROR_TIMEOUT },
  { "Transmit error", SSH_IKEV2_ERROR_XMIT_ERROR },
  { "Cookie required", SSH_IKEV2_ERROR_COOKIE_REQUIRED },
  { "Discard packet", SSH_IKEV2_ERROR_DISCARD_PACKET },
  { "Use IKEv1", SSH_IKEV2_ERROR_USE_IKEV1 },
  { "Server going down", SSH_IKEV2_ERROR_GOING_DOWN },
  { "Send window full", SSH_IKEV2_ERROR_WINDOW_FULL },
  { "SA unusable", SSH_IKEV2_ERROR_SA_UNUSABLE },
  { "Server suspended", SSH_IKEV2_ERROR_SUSPENDED },
#ifdef SSHDIST_IKE_REDIRECT
  { "Redirect limit reached", SSH_IKEV2_ERROR_REDIRECT_LIMIT },
#endif /* SSHDIST_IKE_REDIRECT */
  { NULL, 0 }
};

const char *ssh_ikev2_notify_to_string(SshIkev2NotifyMessageType notify)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_notify_to_string_table, notify);
  if (name == NULL)
    return "unknown";
  return name;
}

const char *ssh_ikev2_error_to_string(SshIkev2Error error)
{
  const char *name;

  if (error != 0 && error < 0x10000)
    name = ssh_find_keyword_name(ssh_ikev2_notify_to_string_table, error);
  else
    name = ssh_find_keyword_name(ssh_ikev2_error_to_string_table, error);
  if (name == NULL)
    return "unknown";
  return name;
}
