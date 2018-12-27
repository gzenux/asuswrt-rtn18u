/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the QuickSec XML configuration module.
*/

#include "common_xmlconf.h"
#ifdef SSHDIST_XML
#include "sshxml.h"
#include "sshxml_dom.h"
#endif /* SSHDIST_XML */

#include "sshdsprintf.h"
#include "sshnameserver.h"
#include "sshdatastream.h"
#include "sshurl.h"


#ifdef SSHDIST_DIRECTORY_HTTP
#include "sshhttp.h"
#endif /* SSHDIST_DIRECTORY_HTTP */

#include "sshfdstream.h"
#include "sshfileio.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshfsm.h"
#include "version.h"

#include "pad_authorization_local.h"
#include "quicksec_pm_low.h"

#include "pad_auth_domain.h"

#ifdef SSHDIST_CERT
/* For raw RSA keys */
#include "sshpkcs1.h"
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_IKE_EAP_AUTH
#include "ssheap.h"
#endif /* SSHDIST_IKE_EAP_AUTH */

#include "ipsec_params.h"

#ifdef SSH_IPSEC_XML_CONFIGURATION

/*************************** Types and definitions ***************************/

/** Predicate to check whether the character `ch' is a whitespace
   character. */
#define SSH_IPM_IS_SPACE(ch) \
((ch) == 0x20 || (ch) == 0x9 || (ch) == 0xd || (ch) == 0xa)

/** Predicate to check whether the character `ch' is a decimal digit. */
#define SSH_IPM_IS_DEC(ch)      \
('0' <= (ch) && (ch) <= '9')

/** Predicate to check whether the character `ch' is a hexadecimal
   digit. */
#define SSH_IPM_IS_HEX(ch)              \
(('0' <= (ch) && (ch) <= '9')           \
 || ('a' <= (ch) && (ch) <= 'f')        \
 || ('A' <= (ch) && (ch) <= 'F'))

/** Convert hexadecimal digit `ch' to its integer value. */
#define SSH_IPM_HEX_TO_INT(ch)  \
('0' <= (ch) && (ch) <= '9'     \
 ? (ch) - '0'                   \
 : ('a' <= (ch) && (ch) <= 'f'  \
    ? (ch) - 'a' + 10           \
    : (ch) - 'A' + 10))

#ifdef DEBUG_LIGHT
#define SSH_XML_VERIFIER(what)                          \
do                                                      \
  {                                                     \
    if (!(what))                                        \
      ssh_fatal("XML verifier did not verify: " #what); \
  }                                                     \
while (0);
#else /** DEBUG_LIGHT */
#define SSH_XML_VERIFIER(what)
#endif /* DEBUG_LIGHT */

/** Information about a policy rule. */
struct SshIpmRuleRec
{
  SshADTBagHeaderStruct adt_header;

  /** The precedence of the rule.  This is also rule's key in the
     bag. */
  SshUInt32 precedence;

  /** Flags. */
  unsigned int seen : 1;        /** Rule seen in the configuration batch. */
  unsigned int unused : 1;      /** Unused in the current configuration. */

  /** Index of the current rule.  This has the value
     `SSH_IPSEC_INVALID_INDEX' if there is no current rule. */
  SshUInt32 rule;

  /** The new rule created by this reconfiguration operation. */
  SshUInt32 new_rule;
};

typedef struct SshIpmRuleRec SshIpmRuleStruct;
typedef struct SshIpmRuleRec *SshIpmRule;

/** Policy object types. */
typedef enum
{
  SSH_IPM_POLICY_OBJECT_NONE,
  SSH_IPM_POLICY_OBJECT_SERVICE,
  SSH_IPM_POLICY_OBJECT_PSK,
  SSH_IPM_POLICY_OBJECT_TUNNEL,
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  SSH_IPM_POLICY_OBJECT_ADDRPOOL
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
} SshIpmPolicyObjectType;

/** Audit module information. */
struct SshIpmAuditRec
{
  SshADTBagHeaderStruct adt_header;

  char *audit_name;
  SshUInt32 format;
  SshUInt32 subsystems;

  unsigned int seen : 1; /** Seen in a previous configuration. */
};

typedef struct SshIpmAuditRec SshIpmAuditStruct;
typedef struct SshIpmAuditRec *SshIpmAudit;


/** A pre-shared key. */
struct SshIpmPskRec
{
  SshPmIdentityType id_type;
  unsigned char *identity;
  SshPmSecretEncoding id_encoding;

  SshPmSecretEncoding encoding;
  unsigned char *secret;
  size_t secret_len;
};

typedef struct SshIpmPskRec SshIpmPskStruct;
typedef struct SshIpmPskRec *SshIpmPsk;

/** A policy object value. */
struct SshIpmPolicyObjectValueRec
{
  SshIpmPolicyObjectType type;
  union
  {
    SshPmService service;
    SshIpmPskStruct psk;
    SshPmTunnel tunnel;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    char *addrpool_name;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  } u;
};

typedef struct SshIpmPolicyObjectValueRec SshIpmPolicyObjectValueStruct;
typedef struct SshIpmPolicyObjectValueRec *SshIpmPolicyObjectValue;

/** Information about policy objects, other than rules.  These objects
   share the same name-space. */
struct SshIpmPolicyObjectRec
{
  SshADTBagHeaderStruct adt_header;

  /** The name of the object.  This is also they key in the ADT
     container. */
  unsigned char *name;
  size_t name_len;

  /** Flags. */
  unsigned int seen : 1;        /** Object seen in the configuration batch. */

  /** The current value. */
  SshIpmPolicyObjectValueStruct value;

  /** The new value from the current reconfiguration. */
  SshIpmPolicyObjectValueStruct new_value;
};

typedef struct SshIpmPolicyObjectRec SshIpmPolicyObjectStruct;
typedef struct SshIpmPolicyObjectRec *SshIpmPolicyObject;

/** Configuration object types. */
typedef enum
{
  SSH_IPM_XMLCONF_PARAMS,
  SSH_IPM_XMLCONF_ENGINE_PARAMS,
  SSH_IPM_XMLCONF_IKE_VERSIONS,
  SSH_IPM_XMLCONF_IKE_GROUPS,
  SSH_IPM_XMLCONF_PFS_GROUPS,
  SSH_IPM_XMLCONF_IKE_ALGORITHMS,
  SSH_IPM_XMLCONF_IKE_WINDOW_SIZE,
#ifdef SSHDIST_IKE_REDIRECT
  SSH_IPM_XMLCONF_IKE_REDIRECT,
  SSH_IPM_XMLCONF_REDIRECT_ADDRESS,
#endif /* SSHDIST_IKE_REDIRECT */
  SSH_IPM_XMLCONF_CA,
  SSH_IPM_XMLCONF_TUNNEL,
  SSH_IPM_XMLCONF_AUTH_DOMAIN,
#ifdef SSHDIST_CERT
  SSH_IPM_XMLCONF_CERTIFICATE,
  SSH_IPM_XMLCONF_CRL,
  SSH_IPM_XMLCONF_PRVKEY,
  SSH_IPM_XMLCONF_PUBKEY,
#endif /* SSHDIST_CERT */
  SSH_IPM_XMLCONF_PSK,
  SSH_IPM_XMLCONF_MANUAL_KEY,
  SSH_IPM_XMLCONF_ACCESS_GROUP,
  SSH_IPM_XMLCONF_PEER,
  SSH_IPM_XMLCONF_LOCAL_IP,
  SSH_IPM_XMLCONF_LOCAL_PORT,
  SSH_IPM_XMLCONF_LOCAL_IFACE,
  SSH_IPM_XMLCONF_CFGMODE_ADDRESS,
  SSH_IPM_XMLCONF_VIRTUAL_IFNAME,
  SSH_IPM_XMLCONF_LIFE,
  SSH_IPM_XMLCONF_IDENTITY,
  SSH_IPM_XMLCONF_TUNNEL_AUTH,
  SSH_IPM_XMLCONF_TUNNEL_ADDRESS_POOL,
  SSH_IPM_XMLCONF_ADDR_POOL,
  SSH_IPM_XMLCONF_SUBNET,
  SSH_IPM_XMLCONF_ADDRESS,
  SSH_IPM_XMLCONF_POLICY,
  SSH_IPM_XMLCONF_RULE,
  SSH_IPM_XMLCONF_SERVICE,
  SSH_IPM_XMLCONF_APPGW,
  SSH_IPM_XMLCONF_SRC,
  SSH_IPM_XMLCONF_DST,
  SSH_IPM_XMLCONF_IFNAME,
  SSH_IPM_XMLCONF_DNS,
#ifdef SSH_IPSEC_TCPENCAP
  SSH_IPM_XMLCONF_TCP_ENCAPS,
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_IPM_XMLCONF_AUDIT,
  SSH_IPM_XMLCONF_GROUP_REF,
  SSH_IPM_XMLCONF_IPV6_PREFIX,
  SSH_IPM_XMLCONF_RADIUS_ACCOUNTING
} SshIpmXmlconfType;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

typedef struct SshIpmRasSubnetConfigRec
SshIpmRasSubnetConfigStruct, *SshIpmRasSubnetConfig;

struct SshIpmRasSubnetConfigRec
{
  SshIpmRasSubnetConfig next;
  unsigned char *address;
};

typedef struct SshIpmRasAddressConfigRec
SshIpmRasAddressConfigStruct, *SshIpmRasAddressConfig;

struct SshIpmRasAddressConfigRec
{
  SshIpmRasAddressConfig next;
  unsigned char *address;
  unsigned char *netmask;
};
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/** A configuration object. */
struct SshIpmXmlconfRec
{
  SshIpmXmlconfType type;
  SshIpmPolicyObject object;

  /** Character data. */
  unsigned char *data;
  size_t data_len;

  union
  {
    struct
    {
      char *file;
    } keycert;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
    struct
    {
      SshIpAddrStruct netmask;
      unsigned char *address_pool_name;
      unsigned char *remote_access_attr_own_ip;
      unsigned char *remote_access_attr_dns;
      unsigned char *remote_access_attr_wins;
      unsigned char *remote_access_attr_dhcp;
      SshUInt32 flags;
      unsigned char *remote_access_ipv6_prefix;
      SshIpmRasSubnetConfig remote_access_attr_subnet_list;
      SshIpmRasAddressConfig remote_access_attr_address_list;
    } addrpool;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_REDIRECT
    struct
    {
      unsigned char *redirect_addr;
      SshUInt8 phase;
    } ike_redirect;
#endif /* SSHDIST_IKE_REDIRECT */

    /** Attributes for Pre-shared keys and aggressive mode secrets. */
    struct
    {
      /** Reference to a named pre-shared key. */
      unsigned char *psk_ref;
      size_t psk_ref_len;

      /** IKE identity. */
      SshPmIdentityType id_type;
      SshPmSecretEncoding id_encoding;
      unsigned char *identity;
      size_t identity_len;

      /** The type of the secret. */
      SshPmSecretEncoding encoding;
      SshUInt32 flags;
    } psk;

    struct
    {
      SshPmRule rule;
      SshUInt32 precedence;
    } rule;

    struct
    {
      char *id;

      /** Configuration data as a DOM tree. */
      SshXmlDom dom;

      /** DOM object attached to parser. */
      Boolean attached;
    } appgw;

    struct
    {
      SshPmService service;
      unsigned char *appgw_config;
      size_t appgw_config_len;
    } service;

    struct
    {
      SshUInt32 transform;
      SshUInt8 ike_versions;
      Boolean default_ike_preferences;
      Boolean default_pfs_preferences;

      /** IKE identity. */
      SshUInt32 identity_flags;
      SshUInt8 remote_identity; /** Boolean, local or remote identity */
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      SshUInt8 second_identity;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
      SshPmIdentityType id_type;
      SshPmSecretEncoding id_encoding;
      unsigned char *identity;
      size_t identity_len;

      /** Authentication domain */
      unsigned char *auth_domain_name;
      size_t auth_domain_name_len;
      SshUInt32 order;

      SshPmTunnel tunnel;
    } tunnel;

    struct
    {
#ifdef SSHDIST_IKE_EAP_AUTH
      SshUInt8 eap_preference_next;
#endif /* SSHDIST_IKE_EAP_AUTH */
      SshPmAuthDomain auth_domain;
    } auth_domain;

    struct
    {
      SshPmLifeType type;
    } life;

    struct
    {
      SshUInt32 precedence;
    } local_address;

    struct
    {
      SshUInt32 flags;
      char *file;
    } ca;

    struct
    {
      SshPmAuthorizationGroup group;
    } group;

    /** Manually keyed SA. */
    struct
    {
      unsigned char *encr_key_i;
      size_t encr_key_i_len;
      unsigned char *encr_key_o;
      size_t encr_key_o_len;

      unsigned char *auth_key_i;
      size_t auth_key_i_len;
      unsigned char *auth_key_o;
      size_t auth_key_o_len;

      SshUInt32 esp_spi_i;
      SshUInt32 esp_spi_o;

      SshUInt32 ah_spi_i;
      SshUInt32 ah_spi_o;

      SshUInt16 ipcomp_cpi_i;
      SshUInt16 ipcomp_cpi_o;
    } manual_key;
#ifdef SSH_IPSEC_TCPENCAP
    struct
    {
      SshIpAddrStruct local_addr;
      SshUInt16 local_port;
      SshIpAddrStruct peer_lo_addr;
      SshIpAddrStruct peer_hi_addr;
      SshUInt16 peer_port;
      SshUInt16 local_ike_port;
      SshUInt16 remote_ike_port;
    } tcp_encaps_config;
#endif /* SSH_IPSEC_TCPENCAP */
  } u;
};

typedef struct SshIpmXmlconfRec SshIpmXmlconfStruct;
typedef struct SshIpmXmlconfRec *SshIpmXmlconf;


#ifdef SSHDIST_IPSEC_NAT
/** A static NAT mapping. */
struct SshIpmStaticNatRec
{
  SshADTBagHeaderStruct adt_header;

  /** Flags. */
  unsigned int seen : 1;        /** Object seen in the configuration batch. */
  unsigned int new_entry : 1;   /** Not configured for the PM yet. */

  SshUInt8 ipproto;

  SshIpAddrStruct ext_ip;
  SshIpAddrStruct int_ip;
  SshUInt16 ext_port;
  SshUInt16 int_port;
};

typedef struct SshIpmStaticNatRec SshIpmStaticNatStruct;
typedef struct SshIpmStaticNatRec *SshIpmStaticNat;

#endif /* SSHDIST_IPSEC_NAT */

/** Legacy authentication client. */
struct SshIpmLegacyAuthClientAuthRec
{
  struct SshIpmLegacyAuthClientAuthRec *next;

  /** Number of references to this object */
  SshUInt32 references;

  /** Flags for which this entry applies to. */
  SshUInt32 flags;

  /** IP address of the gateway. */
  SshIpAddrStruct gateway_ip;

  /** User-name. */
  unsigned char *user_name;
  size_t user_name_len;

  /** Password. */
  unsigned char *password;
  size_t password_len;
};

typedef struct SshIpmLegacyAuthClientAuthRec *SshIpmLegacyAuthClientAuth;

/** Mapping to hold authorization group IDs. */
struct SshIpmAuthGroupIdRec
{
  SshADTBagHeaderStruct adt_header;

  /** The name of the group. */
  unsigned char *name;
  size_t name_len;

  /** Its ID. */
  SshUInt32 group_id;
};

typedef struct SshIpmAuthGroupIdRec SshIpmAuthGroupIdStruct;
typedef struct SshIpmAuthGroupIdRec *SshIpmAuthGroupId;

/** Legacy client authentication methods. */
typedef enum
{
  SSH_IPM_LA_AUTH_NONE,
  SSH_IPM_LA_AUTH_PASSWD,
  SSH_IPM_LA_AUTH_RADIUS
} SshIpmLegacyAuthMethod;

/** HTTP interface for statistics. */
typedef struct SshIpmHttpStatisticsRec *SshIpmHttpStatistics;

/** The depth of the parsing stack. */
#define SSH_IPM_STACK_DEPTH 5


/** Ipm configuration contexts. */

#ifdef SSHDIST_IPSEC_NAT
/** Ipm NAT configuration context. */
typedef struct SshIpmNatConfigRec SshIpmNatConfigStruct, *SshIpmNatConfig;

struct SshIpmNatConfigRec
{
  SshIpmNatConfig next;
  SshPmNatFlags flags;
  char *ifname;
  SshPmNatType nat_type;
};
#endif /* SSHDIST_IPSEC_NAT */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/** An media/IP address pair mapping . */
typedef struct SshIpmMediaConfigRec SshIpmMediaConfigStruct;
typedef struct SshIpmMediaConfigRec *SshIpmMediaConfig;

struct SshIpmMediaConfigRec
{
  SshIpmMediaConfig next;
  unsigned int seen : 1; /** Seen in this configuration. */
  unsigned int old : 1;  /** Seen in a previous configuration. */

  SshIpAddrStruct ip;
  unsigned char mac[6];
  SshUInt32 ifnum;
  SshUInt32 flags;
};

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/** Context data for policy manager. */
struct SshIpmContextRec
{
  /** Flags. */
  unsigned int bootstrap_done : 1; /** Bootstrap configure done for
                                      enabling policy fetch. */

  unsigned int initial_done : 1; /** Initial configure using real
                                     policy done. */
  unsigned int ldap_changed : 1;   /** LDAP servers changed. */
  unsigned int http_interface : 1; /** HTTP interface configured. */

  unsigned int auth_domains : 1;
  unsigned int default_auth_domain_present : 1;
  unsigned int auth_domain_reset_failed : 1;

  unsigned int dns_names_allowed : 1;
  unsigned int dns_configuration_done : 1;

  unsigned int parse_completed : 1;

  unsigned int dtd_specified : 1; /** Have seen DTD spec on doc */

  unsigned int commit_called : 1; /** ssh_pm_commit() has been called. */

  unsigned int commit_failed : 1; /** ssh_pm_commit() has failed. */

  unsigned int engine_params_set : 1; /** engine params were set. */

  unsigned int aborted : 1;       /** Configuration was aborted. */

  /** Time when the system was started. */
  SshTime start_time;

  /** Rules allowing the bootstrap configuration. */
  struct
  {
    SshUInt32 rule;
    unsigned char *traffic_selector;

    /** Success from a bootstrap rule operation. */
    Boolean success;
  } bootstrap;

  /** Pointer to our policy manager object. */
  void * pm;

  /** FSM. */
  SshFSMStruct fsm;

  /** FSM thread taking care of policy reconfiguration. */
  SshFSMThreadStruct thread;

  /** Command line arguments and other static-like parameters. */
  SshIpmParams params;

  /** Ipm Create Callback and its context */
  SshIpmCtxEventCB cb;
  void *cb_ctx;

  /** The configuration stream.  This is resolved from the
     `params.config_file' using the normal system resource
     resolver. */
  struct
  {
    SshStream stream;
    char *stream_name;
    SshXmlDestructorCB destructor_cb;
    void *destructor_cb_context;
  } config;

  /** Prefix, extracted from the `params.config_file'. */
  char *prefix;

  /** XML parser and verifier. */
  SshXmlParser parser;
  SshXmlVerifier verifier;

  /** Completion callback for a configuration file parsing
     operation. */
  SshPmStatusCB parse_status_cb;
  void *parse_status_cb_context;

  /** The result of the parse operation. */
  Boolean parse_result;

  /** A timeout that calls the parse result callback. */
  SshTimeoutStruct timeout;

  /** Rules. */
  SshADTContainer rules;

  /** Audit modules. */
  SshADTContainer audit_modules;

  /** Policy objects, other than rules and audit modules. */
  SshADTContainer policy_objects;

  /** LDAP servers. */
  SshBufferStruct ldap_servers;

  /** PM parameter flags */
  SshUInt32 pm_flags;

  /** Engine params */
  SshEngineParamsStruct engine_params;

  /** Local authorization group module. */
  SshPmAuthorizationLocal authorization;

  /** Legacy authentication method. */
  SshIpmLegacyAuthMethod la_auth_method;

#ifdef SSHDIST_RADIUS
  SshRadiusClient radius_acct_client;
  SshRadiusClientServerInfo radius_acct_servers;
#endif /* SSHDIST_RADIUS */

  /** Mapping from authorization group names to their IDs. */
  SshADTContainer auth_groups;

  /** The next available authorization group ID. */
  SshUInt32 next_group_id;

  /** Legaycy authentication client. */
  SshIpmLegacyAuthClientAuth la_client_auth;

  /** HTTP statistics interface. */
  SshIpmHttpStatistics http_statistics;

  /** Number of references to the HTTP interface. */
  SshUInt32 http_statistics_refcount;

#ifdef SSHDIST_EXTERNALKEY
  SshEkProvider ek_providers;
  SshUInt32 num_ek_providers;
#endif /* SSHDIST_EXTERNALKEY */

  /** The current state of the parsing. */
  SshIpmXmlconf state;
  SshIpmXmlconfStruct stack[SSH_IPM_STACK_DEPTH];

  /** The available precedence space. */
  SshUInt32 precedence_used_min;

  /** The precedence range of the current policy block. */
  SshUInt32 precedence_max;
  SshUInt32 precedence_min;
  SshUInt32 precedence_next;

  /** XML library's completion callback for policy end-element. */
  SshXmlResultCB result_cb;
  void *result_cb_context;

  /** Current refresh flows value. Zero means that there is
     no automatic refresh configured. */
  SshUInt32 refresh_flows;

  /** The smallest refresh value seen so far.  Zero means that there is
     no automatic refresh configured so far. */
  SshUInt32 refresh;

  /** Temporary variables. */
  unsigned char buf[1024];

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /** Media/IP address mappings. */
  SshIpmMediaConfig media_list;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /** Temporary configuration parameters. */
  struct {
#ifdef SSHDIST_IPSEC_NAT
    /** Interface NAT */
    SshIpmNatConfig nat_list;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    /** Internal NAT */
    unsigned char *internal_nat_first;
    unsigned char *internal_nat_last;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

    /** IKE default algorithms */
    SshUInt32 default_ike_algorithms;
  } config_parameters;

  SshOperationHandle sub_operation;
  SshOperationHandle parse_operation;
  SshOperationHandleStruct operation[1];
};

typedef struct SshIpmContextRec SshIpmContextStruct;

/** QuickSec DTD. */
extern const unsigned char quicksec_dtd[];
extern const size_t quicksec_dtd_len;


/******************* Prototypes for internal help functions ******************/




void ssh_ipm_error(SshIpmContext ctx, const char *fmt, ...);
void ssh_ipm_warning(SshIpmContext ctx, const char *fmt, ...);


/************************* HTTP statistics interface *************************/

/** Parameters for the HTTP statistics interface. */
struct SshIpmHttpStatisticsParamsRec
{
  /** The local IP address to listen to.  The default address is
     SSH_IPADDR_ANY. */
  char *address;

  /** The port number on which the HTTP interface is running. */
  SshUInt16 port;

  /** Use frames? */
  Boolean frames;

  /** Refresh interval.  If the value is 0, no refreshing is
     requested. */
  SshUInt32 refresh;
};

typedef struct SshIpmHttpStatisticsParamsRec SshIpmHttpStatisticsParamsStruct;
typedef struct SshIpmHttpStatisticsParamsRec *SshIpmHttpStatisticsParams;

/** Start the HTTP statistics interface for the policy manager `ctx' to
   port `port'.  The argument `frames' specifies whether the interface
   uses frames or not.  The function returns a boolean success
   status. */
Boolean ssh_ipm_http_statistics_start(SshIpmContext ctx,
                                      SshIpmHttpStatisticsParams params);

/** Stop the HTTP statistics interface of the policy manager `ctx'.
   The function returns TRUE if the HTTP statistics interface was
   stopped and FALSE otherwise.  If the function returns FALSE, the
   caller should call the function again at some later time to retry
   stopping the HTTP interface. */
Boolean ssh_ipm_http_statistics_stop(SshIpmContext ctx);


#ifdef SSHDIST_IKE_REDIRECT
/************************ IKE redirect sample filter *************************/
void
ssh_ike_redirect_decision_cb(unsigned char *client_id,
                             size_t client_id_len,
                             SshPmIkeRedirectResultCB result_cb,
                             void *result_cb_context,
                             void *context);
#endif /* SSHDIST_IKE_REDIRECT */

#endif /* SSH_IPSEC_XML_CONFIGURATION */
