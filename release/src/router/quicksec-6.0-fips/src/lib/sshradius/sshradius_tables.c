/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tables describing radius attributes and types.
*/

#include "sshincludes.h"
#include "sshradius_internal.h"

/********************************** Tables **********************************/

#define SSH_T_TEXT              SSH_RADIUS_AVP_VALUE_TEXT
#define SSH_T_STRING            SSH_RADIUS_AVP_VALUE_STRING
#define SSH_T_ADDRESS           SSH_RADIUS_AVP_VALUE_ADDRESS
#define SSH_T_ADDRV6            SSH_RADIUS_AVP_VALUE_IPV6_ADDRESS
#define SSH_T_INTEGER           SSH_RADIUS_AVP_VALUE_INTEGER
#define SSH_T_TIME              SSH_RADIUS_AVP_VALUE_TIME
#define SSH_T_TAG_STRING        SSH_RADIUS_AVP_VALUE_TAG_STRING
#define SSH_T_TAG_INTEGER       SSH_RADIUS_AVP_VALUE_TAG_INTEGER

const SshRadiusAvpInfoStruct ssh_radius_avp_info_table[] =
{
  /* RFC 2865 attributes. */
  {SSH_RADIUS_AVP_USER_NAME,            "User-Name",            SSH_T_TEXT},
  {SSH_RADIUS_AVP_USER_PASSWORD,        "User-Password",        SSH_T_TEXT},
  {SSH_RADIUS_AVP_CHAP_PASSWORD,        "CHAP-Password",        SSH_T_TEXT},
  {SSH_RADIUS_AVP_NAS_IP_ADDRESS,       "NAS-IP-Address",       SSH_T_ADDRESS},
  {SSH_RADIUS_AVP_NAS_PORT,             "NAS-Port",             SSH_T_INTEGER},
  {SSH_RADIUS_AVP_SERVICE_TYPE,         "Service-Type",         SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FRAMED_PROTOCOL,      "Framed-Protocol",      SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FRAMED_IP_ADDRESS,    "Framed-IP-Address",    SSH_T_ADDRESS},
  {SSH_RADIUS_AVP_FRAMED_IP_NETMASK,    "Framed-IP-Netmask",    SSH_T_ADDRESS},
  {SSH_RADIUS_AVP_FRAMED_ROUTING,       "Framed-Routing",       SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FILTER_ID,            "Filter-Id",            SSH_T_TEXT},
  {SSH_RADIUS_AVP_FRAMED_MTU,           "Framed-MTU",           SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FRAMED_COMPRESSION,   "Framed-Compression",   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_LOGIN_IP_HOST,        "Login-IP-Host",        SSH_T_ADDRESS},
  {SSH_RADIUS_AVP_LOGIN_SERVICE,        "Login-Service",        SSH_T_INTEGER},
  {SSH_RADIUS_AVP_LOGIN_TCP_PORT,       "Login-TCP-Port",       SSH_T_INTEGER},
  {SSH_RADIUS_AVP_REPLY_MESSAGE,        "Reply-Message",        SSH_T_TEXT},
  {SSH_RADIUS_AVP_CALLBACK_NUMBER,      "Callback-Number",      SSH_T_STRING},
  {SSH_RADIUS_AVP_CALLBACK_ID,          "Callback-Id",          SSH_T_STRING},
  {SSH_RADIUS_AVP_FRAMED_ROUTE,         "Framed-Route",         SSH_T_TEXT},
  {SSH_RADIUS_AVP_FRAMED_IPX_NETWORK,   "Framed-IPX-Network",   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_STATE,                "State",                SSH_T_STRING},
  {SSH_RADIUS_AVP_CLASS,                "Class",                SSH_T_STRING},
  {SSH_RADIUS_AVP_VENDOR_SPECIFIC,      "Vendor-Specific",      SSH_T_STRING},
  {SSH_RADIUS_AVP_SESSION_TIMEOUT,      "Session-Timeout",      SSH_T_INTEGER},
  {SSH_RADIUS_AVP_IDLE_TIMEOUT,         "Idle-Timeout",         SSH_T_INTEGER},
  {SSH_RADIUS_AVP_TERMINATION_ACTION,   "Termination-Action",   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_CALLED_STATION_ID,    "Called-Station-Id",    SSH_T_STRING},
  {SSH_RADIUS_AVP_CALLING_STATION_ID,   "Calling-Station-Id",   SSH_T_STRING},
  {SSH_RADIUS_AVP_NAS_IDENTIFIER,       "NAS-Identifier",       SSH_T_STRING},
  {SSH_RADIUS_AVP_PROXY_STATE,          "Proxy-State",          SSH_T_STRING},
  {SSH_RADIUS_AVP_LOGIN_LAT_SERVICE,    "Login-LAT-Service",    SSH_T_STRING},
  {SSH_RADIUS_AVP_LOGIN_LAT_NODE,       "Login-LAT-Node",       SSH_T_STRING},
  {SSH_RADIUS_AVP_LOGIN_LAT_GROUP,      "Login-LAT-Group",      SSH_T_STRING},
  {SSH_RADIUS_AVP_FRAMED_APPLETALK_LINK,        "Framed-AppleTalk-Link",
   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FRAMED_APPLETALK_NETWORK,     "Framed-AppleTalk-Network",
   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_FRAMED_APPLETALK_ZONE,        "Framed-AppleTalk-Zone",
   SSH_T_STRING},
  {SSH_RADIUS_AVP_CHAP_CHALLENGE,       "CHAP-Challenge",       SSH_T_STRING},
  {SSH_RADIUS_AVP_NAS_PORT_TYPE,        "NAS-Port-Type",        SSH_T_INTEGER},
  {SSH_RADIUS_AVP_PORT_LIMIT,           "Port-Limit",           SSH_T_INTEGER},
  {SSH_RADIUS_AVP_LOGIN_LAT_PORT,       "Login-LAT-Port",       SSH_T_STRING},

  /* RFC 2866 attributes. */
  {SSH_RADIUS_AVP_ACCT_STATUS_TYPE,     "Acct-Status-Type",     SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_DELAY_TIME,      "Acct-Delay-Time",      SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_INPUT_OCTETS,    "Acct-Input-Octets",    SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_OUTPUT_OCTETS,   "Acct-Output-Octets",   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_SESSION_ID,      "Acct-Session-Id",      SSH_T_TEXT},
  {SSH_RADIUS_AVP_ACCT_AUTHENTIC,       "Acct-Authentic",       SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_SESSION_TIME,    "Acct-Session-Time",    SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_INPUT_PACKETS,   "Acct-Input-Packets",   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_OUTPUT_PACKETS,  "Acct-Output-Packets",  SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_TERMINATE_CAUSE, "Acct-Terminate-Cause", SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_MULTI_SESSION_ID,        "Acct-Multi-Session-Id",
   SSH_T_TEXT},
  {SSH_RADIUS_AVP_ACCT_LINK_COUNT,      "Acct-Link-Count",      SSH_T_INTEGER},

  /* RFC 2867 attributes. */
  {SSH_RADIUS_AVP_ACCT_TUNNEL_CONNECTION,       "Acct-Tunnel-Connection",
   SSH_T_STRING},
  {SSH_RADIUS_AVP_ACCT_TUNNEL_PACKETS_LOST,     "Acct-Tunnel-Packets-Lots",
   SSH_T_INTEGER},

  /* RFC 2868 attributes. */
  {SSH_RADIUS_AVP_TUNNEL_TYPE,                  "Tunnel-Type",
   SSH_T_TAG_INTEGER},
  {SSH_RADIUS_AVP_TUNNEL_MEDIUM_TYPE,           "Tunnel-Medium-Type",
   SSH_T_TAG_INTEGER},
  {SSH_RADIUS_AVP_TUNNEL_CLIENT_ENDPOINT,       "Tunnel-Client-Endpoint",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_SERVER_ENDPOINT,       "Tunnel-Server-Endpoint",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_PASSWORD,              "Tunnel-Password",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_PRIVATE_GROUP_ID,      "Tunnel-Private-Group-ID",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_ASSIGNMENT_ID,         "Tunnel-Assignment-ID",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_PREFERENCE,            "Tunnel-Preference",
   SSH_T_TAG_INTEGER},
  {SSH_RADIUS_AVP_TUNNEL_CLIENT_AUTH_ID,        "Tunnel-Client-Auth-ID",
   SSH_T_TAG_STRING},
  {SSH_RADIUS_AVP_TUNNEL_SERVER_AUTH_ID,        "Tunnel-Server-Auth-ID",
   SSH_T_TAG_STRING},

  /* RFC 2869 attributes. */
  {SSH_RADIUS_AVP_ACCT_INPUT_GIGAWORDS,         "Acct-Input-Gigawords",
   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ACCT_OUTPUT_GIGAWORDS,        "Acct-Output-Gigawords",
   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_EVENT_TIMESTAMP,      "Event-Timestamp",      SSH_T_TIME},



  {SSH_RADIUS_AVP_ARAP_PASSWORD,        "ARAP-Password",        SSH_T_STRING},
  {SSH_RADIUS_AVP_ARAP_FEATURES,        "ARAP-Features",        SSH_T_STRING},
  {SSH_RADIUS_AVP_ARAP_ZONE_ACCESS,     "ARAP-Zone-Access",     SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ARAP_SECURITY,        "ARAP-Security",        SSH_T_INTEGER},
  {SSH_RADIUS_AVP_ARAP_SECURITY_DATA,   "ARAP-Security-Data",   SSH_T_STRING},
  {SSH_RADIUS_AVP_PASSWORD_RETRY,       "Password-Retry",       SSH_T_INTEGER},
  {SSH_RADIUS_AVP_PROMPT,               "Prompt",               SSH_T_INTEGER},
  {SSH_RADIUS_AVP_CONNECT_INFO,         "Connect-Info",         SSH_T_TEXT},
  {SSH_RADIUS_AVP_CONFIGURATION_TOKEN,  "Configuration-Token",  SSH_T_STRING},
  {SSH_RADIUS_AVP_EAP_MESSAGE,          "EAP-Message",          SSH_T_STRING},
  {SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR,        "Message-Authenticator",
   SSH_T_STRING},



  {SSH_RADIUS_AVP_ARAP_CHALLENGE_RESPONSE,      "ARAP-Challenge-Response",
   SSH_T_STRING},
  {SSH_RADIUS_AVP_ACCT_INTERIM_INTERVAL,        "Acct-Interim-Interval",
   SSH_T_INTEGER},
  {SSH_RADIUS_AVP_NAS_PORT_ID,          "NAS-Port-Id",  SSH_T_TEXT},
  {SSH_RADIUS_AVP_FRAMED_POOL,          "Framed-Pool",  SSH_T_STRING},

  /* RFC 3162 attributes. */
  {SSH_RADIUS_AVP_NAS_IPV6_ADDRESS,     "NAS-IPv6-Address",     SSH_T_ADDRV6},



  {SSH_RADIUS_AVP_FRAMED_INTERFACE_ID,  "Framed-Interface-Id",  SSH_T_STRING},



  {SSH_RADIUS_AVP_FRAMED_IPV6_PREFIX,   "Framed-IPv6-Prefix",   SSH_T_STRING},
  {SSH_RADIUS_AVP_LOGIN_IPV6_HOST,      "Login-IPv6-Host",      SSH_T_ADDRV6},
  {SSH_RADIUS_AVP_FRAMED_IPV6_ROUTE,    "Framed-IPv6-Route",    SSH_T_TEXT},
  {SSH_RADIUS_AVP_FRAMED_IPV6_POOL,     "Framed-IPv6-Pool",     SSH_T_STRING},

  /* Non-RFC attributes, defined by IANA/radius. */
  {SSH_RADIUS_AVP_ORIGINATING_LINE_INFO,        "Originating-Line-Info",
   SSH_T_STRING},



















  {0, NULL, 0},
};

const SshKeywordStruct ssh_radius_avp_status_codes[] =
{
  {"Success",           SSH_RADIUS_AVP_STATUS_SUCCESS},
  {"Value too long",    SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG},
  {"Too many",          SSH_RADIUS_AVP_STATUS_TOO_MANY},
  {"Out of memory",     SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY},
  {"Not found",         SSH_RADIUS_AVP_STATUS_NOT_FOUND},
  {NULL, 0},
};

const SshKeywordStruct ssh_radius_url_status_codes[] =
{
  {"Success",                     SSH_RADIUS_URL_STATUS_SUCCESS},
  {"Unknown AVP type",            SSH_RADIUS_URL_UNKNOWN_AVP_TYPE},
  {"Out of memory",               SSH_RADIUS_URL_OUT_OF_MEMORY},
  {"Invalid AVP value",           SSH_RADIUS_URL_INVALID_AVP_VALUE},
  {"Invalid scheme in URL",       SSH_RADIUS_URL_INVALID_SCHEME},
  {"Expected NAS id not in URL",  SSH_RADIUS_URL_EXPECTING_NAS_ID},
  {"AVP-list in URL malformed",   SSH_RADIUS_URL_AVPLIST_MALFORMED},
  {"URL malformed",               SSH_RADIUS_URL_MALFORMED},
  {NULL,0},
};

const SshKeywordStruct ssh_radius_operation_codes[] =
{
  {"Access-Request",         SSH_RADIUS_ACCESS_REQUEST},
  {"Access-Accept",          SSH_RADIUS_ACCESS_ACCEPT},
  {"Access-Reject",          SSH_RADIUS_ACCESS_REJECT},
  {"Accounting-Request",     SSH_RADIUS_ACCOUNTING_REQUEST},
  {"Accounting-Response",    SSH_RADIUS_ACCOUNTING_RESPONSE},
  {"Access-Challenge",       SSH_RADIUS_ACCESS_CHALLENGE},
  {"Status-Server",          SSH_RADIUS_STATUS_SERVER},
  {"Status-Client",          SSH_RADIUS_STATUS_CLIENT},
  {NULL,0},
};

const SshKeywordStruct ssh_radius_client_request_status_codes[] =
{
  {"Success",                   SSH_RADIUS_CLIENT_REQ_SUCCESS},
  {"Malformed request",         SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST},
  {"Insufficient resources",    SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES},
  {"Timed out",                 SSH_RADIUS_CLIENT_REQ_TIMEOUT},
  {"Malformed reply",           SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY},
  {NULL, 0},
};

const SshKeywordStruct ssh_radius_acct_status_types[] =
{
  /* RFC 2866 */
  {"Start",                     1},
  {"Stop",                      2},
  {"Interim-Update",            3},
  {"Accounting-On",             7},
  {"Accounting-Off",            8},

  /* RFC 2867 */
  {"Tunnel-Start",              9},
  {"Tunnel-Stop",               10},
  {"Tunnel-Reject",             11},
  {"Tunnel-Link-Start",         12},
  {"Tunnel-Link-Stop",          13},
  {"Tunnel-Link-Reject",        14},

  {NULL, 0},
};

const SshKeywordStruct ssh_radius_nas_port_types[] =
{
  /* RFC 2865 */
  {"Async",                     SSH_RADIUS_NAS_PORT_TYPE_ASYNC},
  {"Sync",                      SSH_RADIUS_NAS_PORT_TYPE_SYNC},
  {"ISDN Sync",                 SSH_RADIUS_NAS_PORT_TYPE_ISDN_SYNC},
  {"ISDN Async V.120",          SSH_RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V120},
  {"ISDN Async V.110",          SSH_RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V110},
  {"Virtual",                   SSH_RADIUS_NAS_PORT_TYPE_VIRTUAL},
  {"PIAFS",                     SSH_RADIUS_NAS_PORT_TYPE_PIAFS},
  {"HDLC Clear Channel",        SSH_RADIUS_NAS_PORT_TYPE_HDLC_CLEAR},
  {"X.25",                      SSH_RADIUS_NAS_PORT_TYPE_X25},
  {"X.75",                      SSH_RADIUS_NAS_PORT_TYPE_X75},
  {"G.3 FAX",                   SSH_RADIUS_NAS_PORT_TYPE_G3FAX},
  {"SDSL",                      SSH_RADIUS_NAS_PORT_TYPE_SDSL},
  {"ADSL CAP",                  SSH_RADIUS_NAS_PORT_TYPE_ADSL_CAP},
  {"ADSL DMT",                  SSH_RADIUS_NAS_PORT_TYPE_ADSL_DMT},
  {"Ethernet",                  SSH_RADIUS_NAS_PORT_TYPE_ETHERNET},
  {"xDSL",                      SSH_RADIUS_NAS_PORT_TYPE_XDSL},
  {"Cable",                     SSH_RADIUS_NAS_PORT_TYPE_CABLE},
  {"Wireless (Other)",          SSH_RADIUS_NAS_PORT_TYPE_WIRELESS_OTHER},
  {"Wireless IEEE 802.11",      SSH_RADIUS_NAS_PORT_TYPE_WIRELESS_IEEE_802_11},
  {NULL, 0}
};

const SshKeywordStruct ssh_radius_service_types[] =
{
  {"Login",                   SSH_RADIUS_SERVICE_TYPE_LOGIN},
  {"Framed",                  SSH_RADIUS_SERVICE_TYPE_FRAMED},
  {"Callback Login",          SSH_RADIUS_SERVICE_TYPE_CALLBACK_LOGIN},
  {"Callback Framed",         SSH_RADIUS_SERVICE_TYPE_CALLBACK_FRAMED},
  {"Outbound",                SSH_RADIUS_SERVICE_TYPE_OUTBOUND},
  {"Administrative",          SSH_RADIUS_SERVICE_TYPE_ADMINISTRATIVE},
  {"NAS Prompt",              SSH_RADIUS_SERVICE_TYPE_NAS_PROMPT},
  {"Authenticate Only",       SSH_RADIUS_SERVICE_TYPE_AUTHENTICATE_ONLY},
  {"Callback NAS Prompt",     SSH_RADIUS_SERVICE_TYPE_CALLBACK_NAS_PROMPT},
  {"Call Check",              SSH_RADIUS_SERVICE_TYPE_CALL_CHECK},
  {"Callback Administratiave",SSH_RADIUS_SERVICE_TYPE_CALLBACK_ADMINISTRATIVE},
  {NULL, 0}
};

const SshKeywordStruct ssh_radius_framed_protocols[] =
{
  {"PPP",                            SSH_RADIUS_FRAMED_PROTOCOL_PPP},
  {"SLIP",                           SSH_RADIUS_FRAMED_PROTOCOL_SLIP},
  {"ARAP",                           SSH_RADIUS_FRAMED_PROTOCOL_ARAP},
  {"Gandalf",                        SSH_RADIUS_FRAMED_PROTOCOL_GANDALF},
  {"Xylogics proprietary IPX/SLIP",
                                 SSH_RADIUS_FRAMED_PROTOCOL_XYLOGICS_IPX_SLIP},
  {"X.75 Synchronous",               SSH_RADIUS_FRAMED_PROTOCOL_X75_SYNC},
  {NULL, 0}
};

const SshKeywordStruct ssh_radius_vendor_ids[] =
{
  {"Microsoft",                      SSH_RADIUS_VENDOR_ID_MS},
  {NULL,0}
};

const SshKeywordStruct ssh_radius_vendor_ms_subtypes[] =
{
  {"MS-CHAP Response",       SSH_RADIUS_VENDOR_MS_CHAP_RESPONSE},
  {"MS-CHAP Error",          SSH_RADIUS_VENDOR_MS_CHAP_ERROR},
  {"MS-CHAP CPW-1",          SSH_RADIUS_VENDOR_MS_CHAP_PW_1},
  {"MS-CHAP CPW-2",          SSH_RADIUS_VENDOR_MS_CHAP_PW_2},
  {"MS-CHAP LM-Enc-PW",      SSH_RADIUS_VENDOR_MS_CHAP_LM_ENC_PW},
  {"MS-CHAP NT-Enc-PW",      SSH_RADIUS_VENDOR_MS_CHAP_NT_ENC_PW},
  {"MS MPPE Encryption Policy",
                             SSH_RADIUS_VENDOR_MS_MPPE_ENCRYPTION_POLICY},
  {"MS MPPE Encryption Types",
                             SSH_RADIUS_VENDOR_MS_MPPE_ENCRYPTION_TYPES},
  {"MS RAS Vendor",          SSH_RADIUS_VENDOR_MS_RAS_VENDOR},
  {"MS-CHAP Domain",         SSH_RADIUS_VENDOR_MS_CHAP_DOMAIN},

  {"MS-CHAP Challenge",      SSH_RADIUS_VENDOR_MS_CHAP_CHALLENGE},
  {"MS-CHAP MPPE-Keys",      SSH_RADIUS_VENDOR_MS_MPPE_KEYS},
  {"MS BAP Usage",           SSH_RADIUS_VENDOR_MS_BAP_USAGE},
  {"MS Link Utilization Threshold",
                             SSH_RADIUS_VENDOR_MS_LINK_UTILIZATION_THRESHOLD},
  {"MS Link Drop Time Limit",SSH_RADIUS_VENDOR_MS_LINK_DROP_TIME_LIMIT},
  {"MS MPPE Send Key",       SSH_RADIUS_VENDOR_MS_MPPE_SEND_KEY},
  {"MS MPPE Recv Key",       SSH_RADIUS_VENDOR_MS_MPPE_RECV_KEY},
  {"MS RAS Version",         SSH_RADIUS_VENDOR_MS_RAS_VERSION},
  {"MS Old ARAP Password",   SSH_RADIUS_VENDOR_MS_OLD_ARAP_PASSWORD},
  {"MS New ARAP Password",   SSH_RADIUS_VENDOR_MS_NEW_ARAP_PASSWORD},

  {"MS ARAP Change Password Reason",
                             SSH_RADIUS_VENDOR_MS_ARAP_PASSWORD_CHANGE_REASON},
  {"MS Filter",              SSH_RADIUS_VENDOR_MS_FILTER},
  {"MS Acct Auth Type",      SSH_RADIUS_VENDOR_MS_ACCT_AUTH_TYPE},
  {"MS Acct Eap Type",       SSH_RADIUS_VENDOR_MS_ACCT_EAP_TYPE},
  {"MS-CHAP2 Response",      SSH_RADIUS_VENDOR_MS_CHAP2_RESPONSE},
  {"MS-CHAP2 Success",       SSH_RADIUS_VENDOR_MS_CHAP2_SUCCESS},
  {"MS-CHAP2 CPW",           SSH_RADIUS_VENDOR_MS_CHAP2_CPW},
  {"MS Primary DNS Server",  SSH_RADIUS_VENDOR_MS_PRIMARY_DNS_SERVER},
  {"MS Secondary DNS Server", SSH_RADIUS_VENDOR_MS_SECONDARY_DNS_SERVER},

  {"MS Primary NBNS Server", SSH_RADIUS_VENDOR_MS_PRIMARY_NBNS_SERVER},
  {"MS Secondary NBNS Server", SSH_RADIUS_VENDOR_MS_SECONDARY_NBNS_SERVER},
  {"MS ARAP Challenge",      SSH_RADIUS_VENDOR_MS_ARAP_CHALLENGE},

  {NULL,0}
};

/***************************** Public functions *****************************/

const SshRadiusAvpInfoStruct *ssh_radius_avp_info(SshRadiusAvpType type)
{
  int i;

  for (i = 0; ssh_radius_avp_info_table[i].name; i++)
    if (ssh_radius_avp_info_table[i].type == type)
      return &ssh_radius_avp_info_table[i];

  return NULL;
}


const SshRadiusAvpInfoStruct *ssh_radius_avp_info_name(const char *name)
{
  int i;

  for (i = 0; ssh_radius_avp_info_table[i].name; i++)
    {
      if (strcasecmp(ssh_radius_avp_info_table[i].name, name) == 0)
        return &ssh_radius_avp_info_table[i];
    }

  return NULL;
}
