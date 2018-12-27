/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS error codes to string
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshfsm.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshenum.h"

#define SSH_DEBUG_MODULE "SshDnsError"

/* Mapping between error codes and error strings. */
const SshKeywordStruct ssh_dns_response_keywords[] = {
  { "No error", SSH_DNS_OK },
  { "Format error", SSH_DNS_FORMAT_ERROR },
  { "Server error", SSH_DNS_SERVER_FAILURE },
  { "Nonexistent domain", SSH_DNS_NONEXISTENT_DOMAIN },
  { "Unsupported operation", SSH_DNS_UNIMPLEMENTED },
  { "Operation refused by server", SSH_DNS_QUERY_REFUSED },
  { "Name exists when it should not", SSH_DNS_YXDOMAIN },
  { "RR set exists when it should not", SSH_DNS_YXRRSET },
  { "RR set that should exists does not", SSH_DNS_NXRRSET },
  { "Server not authorative for zone", SSH_DNS_NOTAUTH },
  { "Name not contained in zone", SSH_DNS_NOTZONE },

  /* Extended response codes. */
  { "Bad OPT Version", SSH_DNS_BADVERS },
  { "TSIG Signature Failure", SSH_DNS_BADSIG },
  { "Key not recognized", SSH_DNS_BADKEY },
  { "Signature out of time window", SSH_DNS_BADTIME },
  { "Bad TKEY Mode", SSH_DNS_BADMODE },
  { "Duplicate key name", SSH_DNS_BADNAME },
  { "Algorithm not supported", SSH_DNS_BADALG },

  /* Internal codes. These are above 16 bit values, thus they cannot be used by
     extended response codes. */
  { "Out of memory", SSH_DNS_MEMORY_ERROR },
  { "Operation timed out", SSH_DNS_TIMEOUT },
  { "Host is unreachable", SSH_DNS_UNREACHABLE },
  { "Connection refused", SSH_DNS_REFUSED },
  { "Unable to send", SSH_DNS_UNABLE_TO_SEND },
  { "Limit reached", SSH_DNS_LIMIT_REACHED },
  { "Internal error", SSH_DNS_INTERNAL_ERROR },
  { "Error parsing the reply packet", SSH_DNS_PARSE_ERROR },
  { NULL, 0 }
};

/* Convert error code to string. */
const char *ssh_dns_response_code_string(SshDNSResponseCode code)
{
  const char *str;

  str = ssh_find_keyword_name(ssh_dns_response_keywords, code);
  if (str == NULL)
    str = "unknown";
  return str;
}

