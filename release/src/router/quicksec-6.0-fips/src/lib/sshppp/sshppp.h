/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_H
#define SSH_PPP_H 1

#ifdef SSHDIST_RADIUS
#include "sshradius.h"
#endif /* SSHDIST_RADIUS */
#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshstream.h"

/* PPP protocol numbers (see RFC 1661) */

#define SSH_PPP_PID_IPCP 0x8021
#define SSH_PPP_PID_IP 0x0021
#define SSH_PPP_PID_LCP 0xc021
#define SSH_PPP_PID_PAP 0xc023
#define SSH_PPP_PID_CHAP 0xc223
#define SSH_PPP_PID_EAP 0xc227

/* LCP protocol unit types (see RCC 1661) */

#define SSH_LCP_VENDOR_EXTENSION 0
#define SSH_LCP_CONFIGURE_REQUEST 1
#define SSH_LCP_CONFIGURE_ACK 2
#define SSH_LCP_CONFIGURE_NAK 3
#define SSH_LCP_CONFIGURE_REJECT 4
#define SSH_LCP_TERMINATE_REQUEST 5
#define SSH_LCP_TERMINATE_ACK 6
#define SSH_LCP_CODE_REJECT 7
#define SSH_LCP_PROTOCOL_REJECT 8
#define SSH_LCP_ECHO_REQUEST 9
#define SSH_LCP_ECHO_REPLY 10
#define SSH_LCP_DISCARD_REQUEST 11

/* LCP configuration option types (see RFC 1661 and RFC1662) */

#define SSH_LCP_CONFIG_TYPE_MRU 1
#define SSH_LCP_CONFIG_TYPE_ACCM 2
#define SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL 3

#define SSH_LCP_CONFIG_TYPE_QUALITY_PROTOCOL 4
#define SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER 5
#define SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION 7
#define SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION 8

/* IPCP configuration option codes (see RFC 1332) */

#define SSH_IPCP_CONFIG_TYPE_IP_ADDRESSES 1
#define SSH_IPCP_CONFIG_TYPE_IP_COMPRESSION 2
#define SSH_IPCP_CONFIG_TYPE_IP_ADDRESS 3

#define SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY 129
#define SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY 131
#define SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY 130
#define SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY 132

/* Values for  */

#define SSH_PPP_MODE_HLDC 0
#define SSH_PPP_MODE_L2TP 1

/* A reference to a PPP connection object. The object
   represents a PPP connection attached to an input
   and output SshStream through the lifetime of
   the PPP connection.

   PPP connections cannot be reused or restarted
   after the connection has been taken down
   or restarted. */

typedef struct SshPppStateRec *SshPPPHandle;

/************************ SshPppSignal ****************************/

/*
  The SshPppSignal type enumerates the different signals the
  PPP instance can pass back via a callback of type SshPppSignalCB.
*/

typedef enum {

  /* A SSH_PPP_SIGNAL_LCP UP signal denotes that the LCP protocol
     has succesfully completed the link parameter negotiation
     and the link is available for use by other protocols
     and LCP options may be meaningfully queried from
     the SshPPPHandle.
  */

  SSH_PPP_SIGNAL_LCP_UP = 1,

  /* A SSH_PPP_SIGNAL_LCP_DOWN signal states that the LCP
     protocol has left the "Open" state for some reason or
     another. It does not necessarily signify that the
     PPP connection will shutdown.

     A SSH_PPP_SIGNAL_LCP_DOWN signal MAY be followed by another
     SSH_PPP_SIGNAL_LCP_UP signal.

     A SSH_PPP_SIGNAL_LCP_DOWN does signify that all protocol
     traffic on the link should cease untill a SSH_PPP_SIGNAL_LCP_UP
     signal is received, and then all relevant parameters
     should be queried again.
  */

  SSH_PPP_SIGNAL_LCP_DOWN = 2,

  /* A SSH_PPP_SIGNAL_IPCP_UP signal states that the IPCP
     protocol has succesfully completed the negotiation for
     the IPv4 protocol. This means that IP traffic may now
     be transported over the PPP connection and the ipcp
     configuration options may be meaningfully queried from
     the SshPPPHandle.
  */


  SSH_PPP_SIGNAL_IPCP_UP = 3,

  /* A SSH_PPP_SIGNAL_IPCP_DOWN signal states that the IPCP
     protocol has left the "Open" state for some reason or another.
     It does not necessarily signify that the PPP connection
     will shutdown.

     A SSH_PPP_SIGNAL_IPCP_DOWN signal MAY be followed by another
     SSH_PPP_SIGNAL_IPCP_UP signal.

     All IPv4 trafic should cease on the link untill a
     SSH_PPP_SIGNAL_IPCP_UP signal is received again, and
     then all relevant parameters should be re-queried.
  */

  SSH_PPP_SIGNAL_IPCP_DOWN = 4,

  /* A SSH_PPP_SIGNAL_IPCP_FAIL signal states that the
     IPCP protocol has failed. This implies that
     either the IPCP link was terminated, the
     peer rejected the IPCP protocol, or negotiation
     failed.

     No IPv4 traffic should be transported on this
     link untill SSH_PPP_SIGNAL_IPCP_UP signal
     has been received.
  */

  SSH_PPP_SIGNAL_IPCP_FAIL = 5,

  /* This SSH_PPP_SIGNAL_PPP_HALT signal denotes that the PPP
     protocol machines have  halted and the PPP connection
     is in the "Terminate" state.

     No further traffic should take place.
  */

  SSH_PPP_SIGNAL_PPP_HALT = 6,

  /* The SSH_PPP_SIGNAL_SERVER_AUTH_FAIL signal is used to signal
     that authentication of the peer has failed. Note that
     this signal can be received even if this instance is not
     running an authentication protocol if a protocol that does
     mutual authentication is used.

     The callee should immediately begin dropping all packets which
     are not PPP control packets.

     The PPP automaton will begin terminating all PPP control
     protocols immediately. The SSH_PPP_SIGNAL_PPP_HALT
     signal will be sent once this has been performed.
  */

  SSH_PPP_SIGNAL_SERVER_AUTH_FAIL = 7,

  /* The SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL is used to signal
     that the client received an authentication failed message.

     The PPP library will not act on this signal, and attempts
     to negotiate IPCP, even if authentication fails. It is
     expected that if the server does not allow unauthenticated
     access, it will take appropriate action.

     The recipient of this signal does not need to take
     any specific action.
  */

  SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL = 8,

  /* The SSH_PPP_SIGNAL_SERVER_AUTH_OK is used to signal that
     the peer has authenticated itself successfully to the
     server. This means that the PPP session has begun
     negotiating IPCP.
  */

  SSH_PPP_SIGNAL_SERVER_AUTH_OK = 9,

  /* The SSH_PPP_SIGNAL_CLIENT_AUTH_OK is used to signal
     that the peer has authenticated itself succesfully to the
     server.
  */
  SSH_PPP_SIGNAL_CLIENT_AUTH_OK = 10,

  /* The SSH_PPP_SIGNAL_FATAL_ERROR is used to signal
     that the PPP instance has encountered an error it
     can not recover from. The PPP instance will process
     no more packets, and is waiting for a call to
     ssh_ppp_destroy(). The error responsible for this
     signal is most likely a ssh_malloc() failure. */
  SSH_PPP_SIGNAL_FATAL_ERROR = 11
 } SshPppSignal;

/*
   The SshPPPSignalCB type callback is used to pass a signal
   the recipient of the callback.

   The different signals are defined above. The context
   pointer "ctx" contains a value defined by the user
   passed in the SshPppParams structure.
 */

typedef void (*SshPppSignalCB)(void *ctx, SshPppSignal);

/********************* Authentication *********************************/


/* The SshPppAuthType defines a set of values used
   to identify individual authentication protocols
   for the SshPppGetSecretCB callbacks. */

typedef enum {
  /* This type denotes CHAP */
  SSH_PPP_AUTH_CHAP = 1,
  /* This type denotes PAP */
  SSH_PPP_AUTH_PAP = 2,
  /* This type denotes an EAP authentication type */
  SSH_PPP_AUTH_EAP = 3,
  /* This type denotes that an EAP Identity request has been received. */
  SSH_PPP_AUTH_EAP_ID = 4,
  /* MS-CHAPv1 [RFC 2433] */
  SSH_PPP_AUTH_MSCHAPv1 = 5,
  /* MS-CHAPv2 [RFC 2759] */
  SSH_PPP_AUTH_MSCHAPv2 = 6,
  /* MS-CHAPv1 Change Password Protocol v2 */
  SSH_PPP_AUTH_MSCHAP_CHPWv2 = 7,
  /* MS-CHAPv2 Change Password Protocol v3 */
  SSH_PPP_AUTH_MSCHAP_CHPWv3 = 8
} SshPppAuthType;


/* The SshPPPGetSecretCB signals the user that it
   should call ssh_ppp_return_secret(user_ctx, SshUInt8 *buf,
   SshUInt32 buflen)

   The buffer buf (containing buflen bytes) is then used as secret.

   The authentication process WILL not proceed, untill the
   secret is returned, but it may timeout or hang, depending
   on the actual authentication protocol.

   Only one outstanding SshPPPGetSecretCB call per protocol state machine
   is allowed. This means in practice that there may at most be one
   outstanding call for a client connection and one outstanding
   call for a server connection.

   The name of the peer contained in the buffer name of length
   namelen bytes may be NULL, if the peer has not given a name. This
   is typical for some authentication protocols for the client,
   where the authenticator does not state who it is (or is pretending
   to be).

   If this function is called with the authentication type
   SSH_PPP_AUTH_EAP_ID, then no actual secret is necessary,
   merely a call to ssh_ppp_return_secret() with NULL
   as the secret. This allows configuration of RADIUS use
   on a per username basis before the call to *_return_secret()
   using ssh_ppp_configure_radius().
*/

typedef void (*SshPPPGetSecretCB)(SshPPPHandle ppp,
                                  SshPppAuthType auth_type,
                                  void *user_ctx,
                                  void *ppp_ctx,
                                  SshUInt8 *name,
                                  SshUInt32 namelen);

/* The SshPPPGetTokenCB signals the user that it should
   call ssh_ppp_return_token(ppp, eap_type, ppp_ctx, token)
   s.t. token is a SshEapToken of the type requested, tok_type.

   The EAP protocol requiring the token has type "eap_type".

   The callback is otherwise analoguous to a SshPPPGetSecretCB
   callback.

   This callback is called only if EAP authentication methods
   are used, in which case it must be defined. */

#ifdef SSHDIST_EAP
typedef void (*SshPPPGetTokenCB)(SshPPPHandle ppp,
                                 SshPppAuthType auth_type,
                                 SshUInt8 eap_type,
                                 SshEapTokenType tok_type,
                                 void *user_ctx,
                                 void *ppp_ctx,
                                 SshUInt8 *name,
                                 SshUInt32 namelen);
#endif /* SSHDIST_EAP */

/********************* RADIUS support *********************************/

#ifdef SSHDIST_RADIUS

/* This callback is called when a RADIUS reply is sufficient
   to authenticate a used and this callback has been defined
   in SshPppRadiusConfiguration.

   The callee can parse the RADIUS reply using the appropriate
   functions in "sshradius.h".

   If this function returns TRUE, authentication proceeds
   as normal and if this function returns FALSE, the authentication
   is rejected.

   The parameters are:

   ppp        - Pointer to the PPP instance
   auth_type  - Authentication protocol in use (PAP, CHAP, EAP ? )
   status     - request status. normally SSH_RADIUS_CLIENT_REQ_SUCCESS
   request    - pointer to the request resulting in this response
   reply_code - status of request, normally SSH_RADIUS_ACCESS_ACCEPT.

 */

typedef Boolean (*SshPppRadiusRequestCB)(
                                      SshPPPHandle ppp,
                                      SshPppAuthType auth_type,
                                      SshRadiusClientRequestStatus status,
                                      SshRadiusClientRequest request,
                                      SshRadiusOperationCode reply_code,
                                      void *context);

/* RADIUS configuration of PPP instance is provided via this
   structure. The actual configuration instance passed to
   the PPP instance is referenced by the PPP instance, and a
   configuration instance can be shared among several PPP
   instances.

   The fields "client" and "servers" MUST be defined in
   a SshPppRadiusConfigurationRec being used by the sshppp
   library.
*/

typedef struct SshPppRadiusConfigurationRec
{
  /* Client object to use */
  SshRadiusClient client;

  /* Servers to use */
  SshRadiusClientServerInfo servers;

  /* Configuration for EAP protocol, if EAP is to use RADIUS
     the ssheap library RADIUS configuration must be provided
     separately. */
#ifdef SSHDIST_EAP
  SshEapRadiusConfiguration eap_radius_config;
#endif /* SSHDIST_EAP */

  /* Flags regarding parameters we receive from the server */

  /* Use "IP Address" from RADIUS server. If the IP address
     is not provided by the RADIUS server, then this is
     interpreted as a value of "0xFFFFFFFE" and the
     local configuration is used.

     Note that if the RADIUS Framed-IP-Address attribute is respected,
     then it is possible for the IP address to be left unnegotiated
     even if a local configuration exists. The implementation
     must be prepared to handle a situation that the IP address
     is not negotiated. */
  Boolean use_framed_ip_address;

  /* Require that Service-Type = Framed and Framed-Protocol = PPP
     in RADIUS Access-Accept messages (otherwise reject). */
  Boolean require_service_ppp;

  /* Honor RADIUS Framed-MTU if LCP does not negotiate MTU */
  Boolean honor_radius_mtu;

  /* Flags regarding parameters we send to the server */

  /* Authenticate also RADIUS PAP and CHAP Access-Requests */
  Boolean authenticate_access_requests;

  /* Default AVP's for requests */
  SshRadiusUrlAvpSet default_avps;

  /* Callback function which is called for additional parsing of
     RADIUS requests. If so desired.  */
  SshPppRadiusRequestCB radius_req_cb;
} *SshPppRadiusConfiguration, SshPppRadiusConfigurationStruct;

#endif /* SSHDIST_RADIUS */

/********************* Misc. Configuration ******************************/


/* A callback function of SshPPPFrameOutputCB is called by a PPP session
   object, when it desires to provide a buffer for output.

   The data for output begins at address buffer+offset and is len bytes in
   length.

   The buffer must be freed using ssh_xfree() by the caller. */

typedef void (*SshPPPFrameOutputCB)(SshPPPHandle ppp,
                                    void *ctx,
                                    SshUInt8 *buffer,
                                    unsigned long offset,
                                    unsigned long len);

/* A structure used to pass parameters configuring the PPP
   instance operation. */

typedef struct SshPppParamsRec
{
  /* Context pointer for callbacks */
  void *ctx;

  /* The eap_md5_client, chap_client and pap_client
     flags define whether to support EAP MD5-Challenge, CHAP
     or  PAP authentication clients, respectively. If set to
     TRUE, then the created PPP instance will agree
     to authenticate itself using these protocols. */






  SshUInt8 mschapv2_client;
  SshUInt8 mschapv1_client;
  SshUInt8 eap_md5_client;
  SshUInt8 chap_client;
  SshUInt8 pap_client;

  /* The eap_md5_server, chap_server and pap_server flags specify
     the authentication protocols to accept for authentication
     of the peer with. If any of these fields is set to
     TRUE, then authentication of the peer is required
     via one of these protocols. If all of these
     are set to FALSE, then authentication of the peer is not required. */






  SshUInt8 mschapv2_server;
  SshUInt8 mschapv1_server;
  SshUInt8 eap_md5_server;
  SshUInt8 chap_server;
  SshUInt8 pap_server;

  /* The ipcp field defines whether to run IPCP, and hence
     configure IPv4, or not. The legitimate values are either
     TRUE or FALSE. */

  SshUInt8 ipcp;

  /* MRU preferences. LCP will not accept a MRU lower than the value
     in min*mru, nor will it accept a value higher than the value
     in max*mru.

     If either value is set to zero, then the MRU is not bounded
     in that direction (although LCP does attempt to configure
     a sane minimum and maximum value). */

  SshUInt16 min_input_mru;
  SshUInt16 max_input_mru;

  SshUInt16 min_output_mru;
  SshUInt16 max_output_mru;

  /* The no magic parameters forces the rejection of the magic value in
     LCP negotiation and causes all identifiers in LCP protocols to
     start from zero instead of being random. This parameter is intended
     mostly for regression testing using pre-generated batch runs. */

  SshUInt8 no_magic_lcp;

  /* The boolean variable pppoe_framing specifies whether to negotiate
     PPPoE framing. This implies

     - Rejection of ACFC option.
     - Rejection of PFC option.
     - Rejection of ACCM option.
     - Rejection of FCS alternative options. */

  SshUInt8 pppoe_framing;

  /* The frame_mode variable defines sets the PPP session ought to perform
     framing.

     A value of SSH_PPP_MODE_HLDC specifies to use the HLDC-like framing
     defined in RFC 1662.

     A value of SSH_PPP_MODE_L2TP specifies to omit byte-stuffing,
     frame-delimition and checksums.

     If an SshStream is used for input, then each frame is expected to be
     preceeded by 4 bytes (in network byte-order) which contain the length
     of the frame.

     If the ssh_ppp_frame_input() function is used to input frames then these
     4 bytes are not expected to be prepended to a frame.

     The same applies to output, if an SshStream is used for output, then 4
     bytes will be prepended to the frame denoting it's length, and if the
     SshPPPFrameOutputCB callback is used, then the length will be
     supplied as a parameter. */

  SshUInt8 frame_mode;

  /* The name of this system during authentication, if not
     specified then authentication will be attempted without
     one.

     ssh_ppp_session_create() assumes that this buffer will
     be invalid after it returns, and it will take it's
     own copy of the it. */

  SshUInt8 *name;
  unsigned long namelen;

  /* IP address negotiation parameters regarding the peer's IP
     address.

     If peer_ipv4_addr is defined and the peer does not propose
     an acceptable IP address, this address will be proposed
     to the peer (via a Configure NAK), and if the peer does
     not query this address IPCP negotiation will eventually
     fail.

     If peer_ipv4_netaddr and peer_ipv4_mask are both defined,
     then only IP addresses which are in the subnet defined by
     these are considered acceptable for the peer.

     If confirm_only_peer_ip is set, then the PPP instance
     will only ACK legitimate IP's, and NAK any non-legitimate
     values, but the instance will not NAK a case where an IP
     address is not proposed by the peer.

     If confirm_only_peer_ip is not set, then the PPP instance
     will NAK IPCP Configure Requests, untill the peer proposes
     an accepted value, as defined by peer_ipv4_netaddr and
     peer_ipv4_mask.

     To force the peer to commit to a certain IP address during
     IPCP negotiation, own_ipv4_netaddr, own_ipv4_mask and
     own_ipv4_addr must all be set. */

  Boolean only_confirm_ip;

  SshIpAddrStruct peer_ipv4_addr;
  SshIpAddrStruct peer_ipv4_netaddr;
  SshIpAddrStruct peer_ipv4_mask;

  /* IP address negotiation parameters regarding our IP
     address.

     If own_ipv4_netaddr and own_ipv4_mask are both defined,
     then only IP addresses proposed by the peer (via
     a Configure NAK) which are in the subnet defined by
     these are considered acceptable for this instance.

     query_without_ip is a boolean variable. If set, then
     this side of the PPP connection, will not attempt to
     specify an IP address, unless the peer requests it
     via a Configure NAK.

     The IP address proposed to the peer is either
     an acceptable IP address proposed by the peer
     via a Configure NAK or (if own_ipv4_addr is
     defined) the address in own_ipv4_addr. */

  Boolean query_without_ip;

  SshIpAddrStruct own_ipv4_addr;
  SshIpAddrStruct own_ipv4_netaddr;
  SshIpAddrStruct own_ipv4_mask;

  /* The 4 parameters below control negotiation of the peer's
     DNS and NBNS name server configuration using the
     IPCP primary dns server, secondary dns server,
     primary nbns server and secondary nbns server
     options as specified in RFC1877.

     If any of the values below are undefined (as
     in SSH_IP_UNDEFINE()), then the respective
     option will be rejected.

     If the option is defined, then the option
     will be NAK'd if the peer does not propose
     the value for the option specified in the
     parameters below. */

  SshIpAddrStruct peer_dns_primary;
  SshIpAddrStruct peer_dns_secondary;
  SshIpAddrStruct peer_nbns_primary;
  SshIpAddrStruct peer_nbns_secondary;

  /* The 4 parameters below control negotiation of the
     this instances DNS and NBNS name server configuration using
     the IPCP primary dns server, secondary dns server, primary
     nbns server and secondary nbns server options as specified
     in RFC1877.

     If any of the values below are undefined (as in
     SSH_IP_UNDEFINE()), then this instance will not attempt
     to negotiate a value for the parameter.

     If a parameter below is defined, then this triggers
     negotiation of the parameter value using the set
     value as the initial attempt.

     All values proposed by the peer are accepted, including
     obviously illegal ones such as 0.0.0.0 and 255.255.255.255,
     if the peer ACK's these in addition to providing them
     through a NAK.  */

  SshIpAddrStruct own_dns_primary;
  SshIpAddrStruct own_dns_secondary;
  SshIpAddrStruct own_nbns_primary;
  SshIpAddrStruct own_nbns_secondary;

  /* Callbacks used to query for secrets using authentication */

  SshPPPGetSecretCB get_client_secret_cb;
  SshPPPGetSecretCB get_server_secret_cb;

#ifdef SSHDIST_EAP
  /* Callbacks used to query EAP tokens for authentication */

  SshPPPGetTokenCB get_client_eap_token_cb;
  SshPPPGetTokenCB get_server_eap_token_cb;
#endif /* SSHDIST_EAP */

  /* The signal_cb function is called with a suitable signal
     as parameter, whenever there is an event the PPP instance
     wishes to notify about. */

  SshPppSignalCB signal_cb;

  /* If SshStreams are used for I/O, these must be defined. If
     callbacks are used, these both must be NULL. */

  SshStream input_stream;
  SshStream output_stream;

  /* If output_stream is undefined, then the PPP session object will attempt
     to use this function to output complete frames. */

  SshPPPFrameOutputCB output_frame_cb;

  /* RADIUS parameters */
#ifdef SSHDIST_RADIUS
  SshRadiusClient params;
#endif /* SSHDIST_RADIUS */
} *SshPppParams, SshPppParamsStruct;

/*
  ssh_ppp_session_create()

  Create a PPP connection object attached to SshStream's
  for input and output. The call will setup the internal
  plumbing for the PPP protocols, but the protocol
  will be idle untill ssh_ppp_boot() is called.

  Parameters:

  config         is a pointer to a SshPPPParams structure
                 specifying the desired behaviour of the PPP
                 connection during it's lifetime.


  The function returns NULL if insufficient resources are
  available to create the instance.
*/

SshPPPHandle
ssh_ppp_session_create(SshPppParams config);

/*
   This function passes a buffer with a complete PPP frame to
   the PPP session object.

   The frame is expected to reside at address buffer+offset
   and be len bytes in length.

   This function MUST NOT be called if an SshStream
   is used for input.

   The PPP session object will ssh_xfree() the buffer after
   it has finished with it. This implies that the buffer
   ought to have been allocated using ssh_xmalloc().
*/

void
ssh_ppp_frame_input(SshPPPHandle ppp,
                    SshUInt8 *buffer,
                    unsigned long offset,
                    unsigned long len);
/*
   ssh_ppp_boot()

   This starts the PPP connection associated with
   the SshPPPHandle object. If the connection
   is already running, this function has no effect

   Parameters:

   ppp           is a handle to a previously created PPP instance
*/

void ssh_ppp_boot(SshPPPHandle ppp);

/*
  ssh_ppp_destroy()

  This destroys the PPP connection associated with the
  SshPPPHandle object, no graceful closing of the link
  is performed.

  The SshStream's passed to ssh_ppp_session_create()
  will not be used after this function returns by the PPP
  object and may be safely destroyed.

  This function may be called from any callback.

  Parameters:

  ppp           is a handle to a previously created PPP instance
*/

void ssh_ppp_destroy(SshPPPHandle ppp);

/*
  ssh_ppp_halt()

  This function informs the PPP connection to
  gracefully shutdown all links. The PPP connection
  is guaranteed to reach the halted state and call
  ppp_halt_cb() if defined.

  This function may be called from any callback
  or from outside a callback.

  Parameters:

  ppp           is a handle to a previously created PPP instance
*/

void
ssh_ppp_halt(SshPPPHandle ppp);

/*
  Below are defined misc. functions for querying the values
  of misc. parameters negotiated using the PPP connection
  protocols.

  Generally these functions will return interesting values
  (as opposed to the defaults in use untill a successful
  negotiation has been comlpeted) after the corresponding
  *_up_cb() callback has been called.

  The ssh_ppp_get_ipcp_*() functions expect as an
  argument a valid pointer to an SshIpAddrStruct,
  which is then set to the relevant address
  or is undefined.
*/


void ssh_ppp_get_ipcp_peer_ip(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_own_ip(SshPPPHandle ppp, SshIpAddr);

void ssh_ppp_get_ipcp_peer_dns_primary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_peer_dns_secondary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_peer_nbns_primary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_peer_nbns_secondary(SshPPPHandle ppp, SshIpAddr);

void ssh_ppp_get_ipcp_own_dns_primary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_own_dns_secondary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_own_nbns_primary(SshPPPHandle ppp, SshIpAddr);
void ssh_ppp_get_ipcp_own_nbns_secondary(SshPPPHandle ppp, SshIpAddr);

int ssh_ppp_get_lcp_input_pfc(SshPPPHandle ppp);
int ssh_ppp_get_lcp_input_acfc(SshPPPHandle ppp);
SshUInt32 ssh_ppp_get_lcp_input_accm(SshPPPHandle ppp);

int ssh_ppp_get_lcp_output_pfc(SshPPPHandle ppp);
int ssh_ppp_get_lcp_output_acfc(SshPPPHandle ppp);
SshUInt32 ssh_ppp_get_lcp_output_accm(SshPPPHandle ppp);

#ifdef SSHDIST_RADIUS
/*
  The ssh_ppp_get_radius_ip_status() function returns the status
  of the RADIUS IP assignment. It does not guarantee that IPCP
  negotiation has concluded and an IP address has assigned, it
  merely reports how RADIUS has instructed the IP address
  negotiation to be performed.
*/

typedef enum
{
  /* IPCP not configured or some other "no-status
     available" condition */
  SSH_PPP_RADIUS_IP_STATUS_NONE = 0,

  /* RADIUS provided the IP address */
  SSH_PPP_RADIUS_IP_STATUS_RADIUS_CONFIGURED = 1,

  /* The IP address is from the NAS configuration
     (RADIUS returned 255.255.255.254 or RADIUS
     was not configured) */
  SSH_PPP_RADIUS_IP_STATUS_NAS_CONFIGURED = 2,

  /* The IP address was chosen freely by the client
     (RADIUS return 255.255.255.255)*/
  SSH_PPP_RADIUS_IP_STATUS_CLIENT_CONFIGURED = 3
} SshPppRadiusIpStatus;

SshPppRadiusIpStatus
ssh_ppp_get_radius_ip_status(SshPPPHandle ppp);

#endif /* SSHDIST_RADIUS */

/* The PPP specifications require that the PPP implementation
   always be able to receive certain LCP messages
   using MRU 1500.

   Therefore ssh_ppp_get_lcp_input_mru() will always
   return at least 1500.

   ssh_ppp_get_lcp_output_mru() will on the other
   hand return the MRU negotiated using LCP. Note
   that this MAY be below 1500, and is intended
   only for non-LCP traffic. The PPP
   instance may attempt to send messages which
   are 1500 bytes in length, if they are legal.
*/

unsigned long ssh_ppp_get_lcp_input_mru(SshPPPHandle ppp);
unsigned long ssh_ppp_get_lcp_output_mru(SshPPPHandle ppp);


/*
  ssh_ppp_return_secret() is used to return a secret requested via
  the SshPPPGetSecretCB callback. This function must be
  called at most once for each invocation of the callback.

  If ssh_ppp_return_secret() is not invoked at all, then
  no authentication will succeed and eventually the link
  will terminate (signaled by several other callbacks).

  The PPP library assumes that the buffer "buf" is
  invalid after the call returns.

  If buf is NULL and the secret was requested
  for an authentication server, then the authentication
  will be failed using the mechanisms of that protocol.

  If buf is NULL and the secret was requested
  for an authentication client, then the authentication
  client will use the empty string as the secret.
*/

void
ssh_ppp_return_secret(SshPPPHandle ppp,
                      void *ctx,
                      SshUInt8 *buf,
                      SshUInt32 length);


#ifdef SSHDIST_EAP
/*
  ssh_ppp_return_token() is used to return a token requested via
  the SshPPPGetTokenCB callback. This function must be
  called at most once for each invocation of the callback.

  If ssh_ppp_return_token() is not invoked at all, then
  no authentication will succeed and eventually the link
  will terminate (signaled by other callbacks).

  The PPP library assumes that the buffer "buf" is
  invalid after the call returns.

  If token is NULL and the secret was requested
  for an authentication server, then the authentication
  will be failed using the mechanisms of that protocol.

  If token is NULL and the secret was requested
  for an authentication client, then the authentication
  client will attempt to proceed with the protocol using
  an appropriate "empty string" / "nothing" / nul value
  if possible.
*/

void
ssh_ppp_return_token(SshPPPHandle ppp,
                     SshUInt8 eap_type,
                     void *ctx,
                     SshEapToken token);
#endif /* SSHDIST_EAP */

/* This function is used to force the PPP automaton
   to renegotiate all variables, and then continue
   operation.

   If a network control protocol (such as IPCP) was not specified
   in the original configuration, then it will not be instantiated
   in the reconfiguration.

   Callback handlers, context pointers and such are also
   unaffected by this. Only PPP configuration options are
   affected. */

void
ssh_ppp_renegotiate(SshPPPHandle ppp, SshPppParams config);

#ifdef SSHDIST_RADIUS
/* The ssh_ppp_configure_radius function is used to attach
   a SshPppRadiusConfiguration instance to the PPP object.
   The PPP object will directly use the instance provided,
   until it is destroyed or disabled (e.g. by
   ssh_ppp_configure_radius(ppp,NULL).

   The RADIUS configuration can be provided to the PPP
   instance during the authentication phase, before the
   first call to "ssh_ppp_return_secret()"
   for the corresponding round.

   If the authentication protocol is EAP, then the
   call to get_server_secret_cb which has an
   authentication type of SSH_PPP_AUTH_EAP_ID
   which signals that RADIUS should be configured. */

void
ssh_ppp_configure_radius(SshPPPHandle ppp,
                         SshPppRadiusConfiguration config);
#endif /* SSHDIST_RADIUS */

/* Simple function for aiding debugging  */

char*
ssh_ppp_pid_to_string(SshUInt16 pid);

#endif /* SSH_PPP_H */
