/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS RRtypes to string
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

#define SSH_DEBUG_MODULE "SshDnsRRType"

/* Mapping between error codes and error strings. */
const SshKeywordStruct ssh_dns_rrtype_keywords[] = {
  { "Host address (A)", SSH_DNS_RESOURCE_A },
  { "Authoritative server (NS)", SSH_DNS_RESOURCE_NS },
  { "Mail destination (MD)", SSH_DNS_RESOURCE_MD },
  { "Mail forwarder (MF)", SSH_DNS_RESOURCE_MF },
  { "Canonical name (CNAME)", SSH_DNS_RESOURCE_CNAME },
  { "Start of authority zone (SOA)", SSH_DNS_RESOURCE_SOA },
  { "Mailbox domain name (MB)", SSH_DNS_RESOURCE_MB },
  { "Mail group member (MG)", SSH_DNS_RESOURCE_MG },
  { "Mail rename name (MR)", SSH_DNS_RESOURCE_MR },
  { "Null resource record (NULL)", SSH_DNS_RESOURCE_NULL },
  { "Well known service (WKS)", SSH_DNS_RESOURCE_WKS },
  { "Domain name pointer (PTR)", SSH_DNS_RESOURCE_PTR },
  { "Host information (HINFO)", SSH_DNS_RESOURCE_HINFO },
  { "Mailbox information (MINFO)", SSH_DNS_RESOURCE_MINFO },
  { "Mail routing information (MX)", SSH_DNS_RESOURCE_MX },
  { "Text strings (TXT)", SSH_DNS_RESOURCE_TXT },
  { "Responsible person (RP)", SSH_DNS_RESOURCE_RP },
  { "AFS cell database (AFSDB)", SSH_DNS_RESOURCE_AFSDB },
  { "X_25 calling address (X25)", SSH_DNS_RESOURCE_X25 },
  { "ISDN calling address (ISDN)", SSH_DNS_RESOURCE_ISDN },
  { "Router through (RT)", SSH_DNS_RESOURCE_RT },
  { "NSAP address (NSAP)", SSH_DNS_RESOURCE_NSAP },
  { "Reverse NSAP lookup (deprecated) (NSAP_PTR)", SSH_DNS_RESOURCE_NSAP_PTR },
  { "Security signature (SIG)", SSH_DNS_RESOURCE_SIG },
  { "Security key (KEY)", SSH_DNS_RESOURCE_KEY },
  { "X.400 mail mapping (PX)", SSH_DNS_RESOURCE_PX },
  { "Geographical position (GPOS)", SSH_DNS_RESOURCE_GPOS },
  { "IP6 Address (AAAA)", SSH_DNS_RESOURCE_AAAA },
  { "Location Information (LOC)", SSH_DNS_RESOURCE_LOC },
  { "Next Valid Name in Zone (NXT)", SSH_DNS_RESOURCE_NXT },
  { "Endpoint identifier (EID)", SSH_DNS_RESOURCE_EID },
  { "Nimrod locator (NIMLOC)", SSH_DNS_RESOURCE_NIMLOC },
  { "Server selection (SRV)", SSH_DNS_RESOURCE_SRV },
  { "ATM Address (ATMA)", SSH_DNS_RESOURCE_ATMA },
  { "Naming Authority PoinTeR (NAPTR)", SSH_DNS_RESOURCE_NAPTR },
  { "Key Exchanger (KX)", SSH_DNS_RESOURCE_KX },
  { "Certificate (CERT)", SSH_DNS_RESOURCE_CERT },
  { "A6 (A6)", SSH_DNS_RESOURCE_A6 },
  { "DNAME (DNAME)", SSH_DNS_RESOURCE_DNAME },
  { "SINK (SINK)", SSH_DNS_RESOURCE_SINK },
  { "OPT (OPT)", SSH_DNS_RESOURCE_OPT },
  { "APL (APL)", SSH_DNS_RESOURCE_APL },
  { "Delegation Signer (DS)", SSH_DNS_RESOURCE_DS },
  { "SSH Key Fingerprint (SSHFP)", SSH_DNS_RESOURCE_SSHFP },
  { "RRSIG (RRSIG)", SSH_DNS_RESOURCE_RRSIG },
  { "NSEC (NSEC)", SSH_DNS_RESOURCE_NSEC },
  { "DNSKEY (DNSKEY)", SSH_DNS_RESOURCE_DNSKEY },
  { "User (finger) information (UINFO)", SSH_DNS_RESOURCE_UINFO },
  { "User ID (UID)", SSH_DNS_RESOURCE_UID },
  { "Group ID (GID)", SSH_DNS_RESOURCE_GID },
  { "Unspecified format (binary data) (UNSPEC)", SSH_DNS_RESOURCE_UNSPEC },

  /* Query typedef values which do not appear in resource records */
  { "Transaction Key (TKEY)", SSH_DNS_QUERY_TKEY },
  { "Transaction Signature (TSIG)", SSH_DNS_QUERY_TSIG },
  { "Incremental zone transfer (IXFR)", SSH_DNS_QUERY_IXFR },
  { "Transfer zone of authority (AXFR)", SSH_DNS_QUERY_AXFR },
  { "Transfer mailbox records (MAILB)", SSH_DNS_QUERY_MAILB },
  { "Transfer mail agent records (MAILA)", SSH_DNS_QUERY_MAILA },
  { "Wildcard match (ANY)", SSH_DNS_QUERY_ANY },
  { NULL, 0 }
};

/* Convert error types to string. */
const char *ssh_dns_rrtype_string(SshDNSRRType type)
{
  const char *str;

  str = ssh_find_keyword_name(ssh_dns_rrtype_keywords, type);
  if (str == NULL)
    str = "unknown";
  return str;
}

