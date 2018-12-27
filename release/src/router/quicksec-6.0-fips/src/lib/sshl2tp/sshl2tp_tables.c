/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SSH keyword tables to give printable names for various constants in
   the L2TP.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

const SshKeywordStruct ssh_l2tp_control_msg_types[] =
{
  {"Reserved0",         SSH_L2TP_CTRL_MSG_RESERVED0},
  {"SCCRQ",             SSH_L2TP_CTRL_MSG_SCCRQ},
  {"SCCRP",             SSH_L2TP_CTRL_MSG_SCCRP},
  {"SCCCN",             SSH_L2TP_CTRL_MSG_SCCCN},
  {"StopCCN",           SSH_L2TP_CTRL_MSG_STOPCCN},
  {"Reserved5",         SSH_L2TP_CTRL_MSG_RESERVED5},
  {"HELLO",             SSH_L2TP_CTRL_MSG_HELLO},

  {"OCRQ",              SSH_L2TP_CTRL_MSG_OCRQ},
  {"OCRP",              SSH_L2TP_CTRL_MSG_OCRP},
  {"OCCN",              SSH_L2TP_CTRL_MSG_OCCN},
  {"ICRQ",              SSH_L2TP_CTRL_MSG_ICRQ},
  {"ICRP",              SSH_L2TP_CTRL_MSG_ICRP},
  {"ICCN",              SSH_L2TP_CTRL_MSG_ICCN},
  {"Reserved13",        SSH_L2TP_CTRL_MSG_RESERVED13},
  {"CDN",               SSH_L2TP_CTRL_MSG_CDN},

  {"WEN",               SSH_L2TP_CTRL_MSG_WEN},

  {"SLI",               SSH_L2TP_CTRL_MSG_SLI},

  /* Internal "ZLB" message type. */
  {"ZLB",               SSH_L2TP_CTRL_MSG_ZLB},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_avp_types[] =
{
  {"Message Type",              SSH_L2TP_AVP_MESSAGE_TYPE},
  {"Result Code",               SSH_L2TP_AVP_RESULT_CODE},
  {"Protocol Version",          SSH_L2TP_AVP_PROTOCOL_VERSION},
  {"Framing Capabilities",      SSH_L2TP_AVP_FRAMING_CAPABILITIES},
  {"Bearer Capabilities",       SSH_L2TP_AVP_BEARER_CAPABILITIES},
  {"Tie Breaker",               SSH_L2TP_AVP_TIE_BREAKER},
  {"Firmware Revision",         SSH_L2TP_AVP_FIRMWARE_REVISION},
  {"Host Name",                 SSH_L2TP_AVP_HOST_NAME},
  {"Vendor Name",               SSH_L2TP_AVP_VENDOR_NAME},
  {"Assigned Tunnel ID",        SSH_L2TP_AVP_ASSIGNED_TUNNEL_ID},
  {"Receive Window Size",       SSH_L2TP_AVP_RECEIVE_WINDOW_SIZE},
  {"Challenge",                 SSH_L2TP_AVP_CHALLENGE},
  {"Q.931 Cause Code",          SSH_L2TP_AVP_Q931_CAUSE_CODE},
  {"Challenge Response",        SSH_L2TP_AVP_CHALLENGE_RESPONSE},
  {"Assigned Session ID",       SSH_L2TP_AVP_ASSIGNED_SESSION_ID},
  {"Call Serial Number",        SSH_L2TP_AVP_CALL_SERIAL_NUMBER},
  {"Minimum BPS",               SSH_L2TP_AVP_MINIMUM_BPS},
  {"Maximum BPS",               SSH_L2TP_AVP_MAXIMUM_BPS},
  {"Bearer Type",               SSH_L2TP_AVP_BEARER_TYPE},
  {"Framing Type",              SSH_L2TP_AVP_FRAMING_TYPE},

  {"unspecified",               SSH_L2TP_AVP_UNSPECIFIED20},

  {"Called Number",             SSH_L2TP_AVP_CALLED_NUMBER},
  {"Calling Number",            SSH_L2TP_AVP_CALLING_NUMBER},
  {"Sub-Address",               SSH_L2TP_AVP_SUB_ADDRESS},
  {"(Tx) Connect Speed",        SSH_L2TP_AVP_CONNECT_SPEED},
  {"Physical Channel ID",       SSH_L2TP_AVP_PHYSICAL_CHANNEL_ID},
  {"Initial Received LCP CONFREQ",
   SSH_L2TP_AVP_INITIAL_RECEIVED_LCP_CONFREQ},
  {"Last Sent LCP CONFREQ",     SSH_L2TP_AVP_LAST_SENT_LCP_CONFREQ},
  {"Last Received LCP CONFREQ", SSH_L2TP_AVP_LAST_RESEIVED_LCP_CONFREQ},
  {"Proxy Authen Type",         SSH_L2TP_AVP_PROXY_AUTHEN_TYPE},
  {"Proxy Authen Name",         SSH_L2TP_AVP_PROXY_AUTHEN_NAME},
  {"Proxy Authen Challenge",    SSH_L2TP_AVP_PROXY_AUTHEN_CHALLENGE},
  {"Proxy Authen ID",           SSH_L2TP_AVP_PROXY_AUTHEN_ID},
  {"Proxy Authen Response",     SSH_L2TP_AVP_PROXY_AUTHEN_RESPONSE},
  {"Call Errors",               SSH_L2TP_AVP_CALL_ERRORS},
  {"ACCM",                      SSH_L2TP_AVP_ACCM},
  {"Random Vector",             SSH_L2TP_AVP_RANDOM_VECTOR},
  {"Private Group ID",          SSH_L2TP_AVP_PRIVATE_GROUP_ID},
  {"Rx Connect Speed",          SSH_L2TP_AVP_RX_CONNECT_SPEED},
  {"Sequencing Required",       SSH_L2TP_AVP_SEQUENCING_REQUIRED},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_ssh_avp_types[] =
{
  {"SSH Transform Index",       SSH_L2TP_SSH_AVP_TRANSFORM_INDEX},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_proxy_authen_types[] =
{
  {"Reserved",                  SSH_L2TP_PROXY_AUTHEN_RESERVED0},

  {"Textual username/password exchange",
   SSH_L2TP_PROXY_AUTHEN_USERNAME_PASSWORD},

  {"PPP CHAP",                  SSH_L2TP_PROXY_AUTHEN_PPP_CHAP},
  {"PPP PAP",                   SSH_L2TP_PROXY_AUTHEN_PPP_PAP},
  {"No Authentication",         SSH_L2TP_PROXY_AUTHEN_NO_AUTHENTICATION},
  {"Microsoft CHAP Version 1",  SSH_L2TP_PROXY_AUTHEN_MSCHAPV1},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_tunnel_result_codes[] =
{
  {"Reserved",
   SSH_L2TP_TUNNEL_RESULT_RESERVED},

  {"General request to clear control connection",
   SSH_L2TP_TUNNEL_RESULT_TERMINATED},

  {"General error",
   SSH_L2TP_TUNNEL_RESULT_ERROR},

  {"Control channel already exists",
   SSH_L2TP_TUNNEL_RESULT_ALREADY_EXISTS},

  {"Requester is not authorized to establish a control channel",
   SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED},

  {"The protocol version of the requester is not supported",
   SSH_L2TP_TUNNEL_RESULT_UNSUPPORTED_PROTOCOL},

  {"Requester is being shut down",
   SSH_L2TP_TUNNEL_RESULT_SHUT_DOWN},

  {"Finite State Machine error",
   SSH_L2TP_TUNNEL_RESULT_FSM_ERROR},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_session_result_codes[] =
{
  {"Reserved",
   SSH_L2TP_SESSION_RESULT_RESERVED},

  {"Call disconnected due to loss of carrier",
   SSH_L2TP_SESSION_RESULT_CARRIER_LOST},

  {"Call disconnected due to general error",
   SSH_L2TP_SESSION_RESULT_ERROR},

  {"Call disconnected for administrative reasons",
   SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE},

  {"Call failed due to lack of appropriate facilities being available "
   "(temporary condition)",
   SSH_L2TP_SESSION_RESULT_TEMPORARY_UNAVAILABLE},

  {"Call failed due to lack of appropriate facilities being available "
   "(permanent condition)",
   SSH_L2TP_SESSION_RESULT_PERMANENTLY_UNAVAILABLE},

  {"Invalid destination",
   SSH_L2TP_SESSION_RESULT_INVALID_DESTINATION},

  {"Call failed due to no carrier detected",
   SSH_L2TP_SESSION_RESULT_NO_CARRIER},

  {"Call failed due to detection of a busy signal",
   SSH_L2TP_SESSION_RESULT_BUSY},

  {"Call failed due to lack of a dial tone",
   SSH_L2TP_SESSION_RESULT_NO_DIAL_TONE},

  {"Call was not established within time allowed by LAC",
   SSH_L2TP_SESSION_RESULT_TIMEOUT},

  {"Call was connected but no appropriate framing was detected",
   SSH_L2TP_SESSION_RESULT_INVALID_FRAMING},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_error_codes[] =
{
  {"No general error",
   SSH_L2TP_ERROR_NO_GENERAL_ERROR},

  {"No control connection exists yet for this LAC-LNS pair",
   SSH_L2TP_ERROR_NO_CONTROL_CONNECTION},

  {"Length is wrong",
   SSH_L2TP_ERROR_LENGTH_IS_WRONG},

  {"One of the field values was out of range or reserved field was "
   "non-zero",
   SSH_L2TP_ERROR_INVALID_VALUE},

  {"Insuffucient resources to handle this operation now",
   SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES},

  {"The Session ID is invalid in this context",
   SSH_L2TP_ERROR_INVALID_SESSION_ID},

  {"A generic vendor-specific error occurred in the LAC",
   SSH_L2TP_ERROR_GENERIC},

  {"Try another",
   SSH_L2TP_ERROR_TRY_ANOTHER},

  {"Session or tunnel was shutdown due to receipt of an unknown AVP "
   "with the Mandatory-bit set",
   SSH_L2TP_ERROR_UNKNOWN_MANDATORY_AVP},

  {NULL, 0},
};


const SshKeywordStruct ssh_l2tp_thread_exceptions[] =
{
  {"Thread Shutdown",   SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN},
  {"Thread Destroy",    SSH_L2TP_THREAD_EXCEPTION_DESTROY},
  {"Thread Cleanup",    SSH_L2TP_THREAD_EXCEPTION_CLEAN_UP},
  {NULL, 0},
};
