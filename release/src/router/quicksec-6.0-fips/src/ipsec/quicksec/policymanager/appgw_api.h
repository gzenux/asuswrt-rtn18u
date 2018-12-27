/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   API used by application gateway implementations. This API runs on the
   application gateway host. Application gateway writers should write
   against this API.
*/

#ifndef APPGW_API_H
#define APPGW_API_H

#include "sshinet.h"
#include "sshudp.h"
#include "sshstream.h"
#include "sshoperation.h"
#include "quicksec_pm.h"

/** Callback function type for the destructor for the user_context
    field of the SshAppgwContext. */
typedef void (*SshAppgwUserCtxDestructor)(void *user_context);

/** Context data structure for an application gateway instance.
    Aapplication gateway framework creates one instance of this data
    structure whenever a new connection to the application gateway is
    made.  The instance remains valid until function ssh_appgw_done()
    is called for it. This data structure both provides information
    about the new connection to the application gateway, and can also
    be modified by the application gateway instance to store its own
    data. */
typedef struct SshAppgwContextRec
{
  /** Connection to the initiator.  This is a valid stream for TCP
      connections, and NULL for UDP connections. */
  SshStream initiator_stream;

  /** Connection to the responder.  This is a valid stream for TCP
      connections, and NULL for UDP connections. */
  SshStream responder_stream;

  /** UDP listeners for sending UDP packets to the initiator */
  SshUdpListener initiator_listener;
  /** UDP listeners for sending UDP packets to the responder */
  SshUdpListener responder_listener;

  /** Original IP address of the initiator when the connection arrived
      at the firewall. */
  SshIpAddrStruct initiator_ip;
  /** Original port of the initiator when the connection arrived at
      the firewall. */
  SshUInt16 initiator_port;

  /** Original IP address of the responder when the connection arrived
      at the firewall. */
  SshIpAddrStruct responder_orig_ip;
  /** Original port of the responder when the connection arrived at
      the firewall. */
  SshUInt16 responder_orig_port;

  /** Original IP address of the responder when the connection arrived
      at the firewall.  This can differ from the values of
      `responder_orig_ip' and `responder_orig_port' if the application
      gateway specified SSH_APPGW_F_REDIRECT and it set new
      destination address for the connection. */
  SshIpAddrStruct responder_ip;

  /** Original port of the responder when the connection arrived at
      the firewall. See field 'responder_ip' for details. */
  SshUInt16 responder_port;

  /** IP address of the initiator, as seen by the responder. */
  SshIpAddrStruct initiator_ip_after_nat;
  /** IP port of the initiator, as seen by the responder. */
  SshUInt16 initiator_port_after_nat;

  /** IP address of the responder, as seen by the responder.  This is
      the address that is used by the appgw framework internally when
      creating the responder stream for TCP.  Note that this will
      differ from responder_ip if coming from outside to inside the
      firewall using a static NAT mapping. */
  SshIpAddrStruct responder_ip_after_nat;
  /** IP port of the responder, as seen by the responder. See
      'responder_ip_after_nat for details. */
  SshUInt16 responder_port_after_nat;

  /** Tunneling information for auditing, where the packet came from. */
  SshUInt32 from_tunnel_id;
  /** Tunneling information for auditing, where the packet is going to. */
  SshUInt32 to_tunnel_id;

  /** An unique identifier for the gateway service object that applied
      this application level gateway for the traffic. */
  SshUInt32 service_id;

  /** A human readable name for the appgw instance. For use in logging.
      It may be NULL. */
  char *service_name;

  /** An unique identifier for the appgw connection. This is used
      primarily in auditing for associating events to each other. */
  SshUInt32 conn_id;

  /** This is NULL for normal new connections; however, if the
      connection was made using a tunnel opened using the
      ssh_appgw_open call with SSH_APPGW_OPEN_THISGW, then this will
      point to the original appgw context that was passed as argument
      to ssh_appgw_open.

      If that appgw context has already been destroyed using
      ssh_appgw_done, then this callback will never happen and any
      attempt to connect the opened port will be denied.

      Note that there is no explicit function to notify the master
      context if a context referencing it is destroyed.  However, the
      `user_destructor' field below can be used to implement this by
      adding a destructor that notifies a master context whose address
      is stored in `user_context', if needed. */
  struct SshAppgwContextRec *master;

  /** Configuration data for an application gateway used by a service
      definition. This data is provided by the policy manager. The
      policymanager usually receives this binary blob via the
      ssh_pm_service_set_appgw_config() call. This configuration data
      is configured for the service, identified by the `service_id'.
      This is valid only for SSH_APPGW_UPDATE_CONFIG actions. */
  const unsigned char *config_data;
  /** Length of the confiuration data 'config_data' in octets. */
  size_t config_data_len;

  /** Context pointer used internally by the framework.  This should
      not be touched by application gateways. */
  void *system_context;

  /** Context pointer for use by application gateway implementations.
      This is initialized to NULL when SshAppgwCB is called with
      SSH_APPGW_NEW_INSTANCE, and can be set by the application
      gateway implementation to an arbitrary value.  This will remain
      valid until ssh_appgw_done is called, and is not used in any way
      by the framework. */
  void *user_context;

  /** Callback function that will be called by ssh_appgw_done() to
      free the user_context field.  This is initialized to NULL
      function pointer by the system when the context is created, and
      needs to be set by the application gateway implementation if
      needed.  If this is NULL function pointer, then user_context
      will be automatically freed using ssh_free if it is
      non-NULL. */
  SshAppgwUserCtxDestructor user_destructor;

  /** These flag value denotes whether an audit event has been
      generated within an appgw callback function or at all. Normally
      the appgw framework should NEVER touch these flag, but if it
      wishes to suppress the generation of any default events it might
      want to set these flag in a callback. */
  unsigned int audit_event_generated;
  unsigned int session_end_event_generated;
} SshAppgwContextStruct, *SshAppgwContext;


/** A structure for providing the necessary configuration data for
    registering an appgw instance. This structure is provided to
    appgw_register - API. */
typedef struct SshAppgwParamsRec
{
  /** Identification of appgw. Must be set. Maximum length is
      SSH_APPGW_MAX_IDENT_LEN bytes. */
  const char *ident;

  /** A printable name of appgw. Can be NULL. */
  const char *printable_name;

  /** Version of implementation */
  SshUInt32 version;

  /** IP protocol the appgw handles */
  SshUInt8 ipproto;

  /** Initial flow idle timeout in seconds. If set to 0 then a timeout
      SSH_APPGW_DEFAULT_TIMEOUT is used. */
  SshUInt32 flow_idle_timeout;

  /** Appgw forced port, see ssh_appgw_open_port(). Also note, when
      using this, should reserve space not used by random port
      mechanisms. */
  SshUInt16 forced_port;
} *SshAppgwParams, SshAppgwParamsStruct;

/** This call terminates any processing of the application gateway
    request indicated by `ctx'.

    The `responder_stream' and `initiator_stream' fields are
    automatically closed if they are non-NULL.  Any ports dynamically
    opened using ssh_appgw_open() with this context are destroyed and
    active connections opened using them are forcibly terminated.
    This automatically closes and frees any streams referenced from
    ctx, unless the fields have been set to NULL.  `ctx' is freed by
    this call.  `ctx->user_context' is automatically freed by this
    function.

    See also description for the user_destructor field above; it can
    be used to free streams and other memory stored behind the
    user_context pointer. */
void ssh_appgw_done(SshAppgwContext ctx);

/** Completes an SSH_APPGW_REDIRECT action for the context `ctx'.  The
    arguments `new_responder_ip' and `new_responder_port' specify the
    new responder for the connection. */
void ssh_appgw_redirect(SshAppgwContext ctx,
                        const SshIpAddr new_responder_ip,
                        SshUInt16 new_responder_port);

/** Audit an event associated with an appgw connection.  The framework
    adds the relevant parameters to the audit message such as a
    description of the session and so forth unless they are explicitly
    specified by the caller (and hence overriden).

    The following parameter values are provided by the appgw framework
    unless a value is provided in the variable arguments list:

   - SSH_AUDIT_IPPROTO
   - SSH_AUDIT_SOURCE_ADDRESS
   - SSH_AUDIT_DESTINATION_ADDRESS
   - SSH_AUDIT_SOURCE_PORT
   - SSH_AUDIT_DESTINATION_PORT

   The following parameter values are ALWAYS provided by the
   framework:

   - SSH_APPGW_EVENT_SOURCE */
void ssh_appgw_audit_event(SshAppgwContext ctx,
                           SshAuditEvent event,
                           ...);

/** This callback function will be called when the operation requested
    by ssh_appgw_open_port() has been completed.  `success' will be TRUE
    if the port was successfully opened, and FALSE if it failed. */

typedef void (*SshAppgwOpenCB)(SshAppgwContext ctx,
                               Boolean success,
                               const SshIpAddr new_dst_ip,
                               SshUInt16 new_dst_port,
                               SshUInt32 open_port_handle,
                               void *context);

/** This function call opens an auxiliary channel related to the
    original connection indicated by `ctx'.  One can also view this as
    a temporary rule that passed data through the firewall.

    This used e.g. to open ports for the data channels in FTP, or
    channel for RTP traffic in case of SIP.

    If `src_port' is 0, then connection from any port on that host to
    the given port is allowed.  This will call `callback' when the
    port has been opened (or attempt to do so has failed).

    If the SSH_APPGW_OPEN_THISGW flag is specified, then the
    connection to the given port - which is guaranteed not to occur
    before the callback has been called - will be passed to the same
    application gateway (with ctx->master pointing to the ctx given as
    argument to this function).

    If SSH_APPGW_OPEN_MULTIPLE is specified, then the connection can
    be used multiple times (UDP connections can always be used
    multiple times, unless prevented by an application gateway using
    the THISGW flag).

    This always opens a bidirectional channel.

    This function is used for several purposes:

    - to dynamically open ports (data channels) from the source to the
      destination, or vice versa (e.g. FTP data channels in
      active/passive mode).  In this case the gateway would specify
      SSH_APPGW_OPEN_THISGW to gain access to data transmitted using the
      data channel (e.g. for virus checking), and would leave it out to
      let the data flow directly without going through a gateway).  If
      SSH_APPGW_OPEN_MULTIPLE is not specified, the port can be used
      exactly once, and must be re-opened for the next data transfer
      (which would normally be the desired behavior for FTP).

    - to open dynamic ports for services that allocate port numbers
      using a portmapper, such as some RPC services.  In this case, the
      SSH_APPGW_OPEN_MULTIPLE flag would likely to be specified to allow
      the allocated port to be used for multiple RPC messages.  If the
      RPC messages themselves need to be processed by the application
      gateway, then SSH_APPGW_OPEN_THISGW needs to be specified (in
      which case they will get sent to the same gateway, which may then
      have its internal multiplexing. SSH_APPGW_OPEN_UDP would typically
      also be specified in the RPC case, since most RPC services are
      UDP-based.

  Any ports opened using this function are automatically closed when
  ssh_appgw_done() is called for the master stream (one given as
  argument to this function), or when the master stream times out.  An
  application gateway MUST take care not to open an unlimited number
  of ports.  For example, an FTP gateway should call
  ssh_appgw_close_port() for the data channel before opening the next
  data channel.  There is no fixed limit on the number of ports that
  can be simultaneously open, however.

  The AppgwParams parameter can be used to pass in a new ipproto or
  flow_idle_timeout value. If NULL, then the values are the same as
  those of the initially created trigger rule.

  This returns an operation handle, which allows the operation to be
  aborted by calling ssh_operation_abort for the handle before the
  callback has been called. */

/** Send new conn to same appgw instance */
#define SSH_APPGW_OPEN_THISGW   0x00000001
/** Mapping created can be used multiple times */
#define SSH_APPGW_OPEN_MULTIPLE 0x00000002
/** Initiator will connect port on Responder */
#define SSH_APPGW_OPEN_FROM_INITIATOR 0x00000004
/** Appgw forces port on parameters, do not allocate it from framework. */
#define SSH_APPGW_OPEN_FORCED   0x00000008

SshOperationHandle ssh_appgw_open_port(SshAppgwContext ctx,
                                       SshAppgwParams params,
                                       SshUInt16 src_port, /** usually 0 */
                                       SshUInt16 dst_port,
                                       SshUInt32 flags,
                                       SshAppgwOpenCB callback, void *context);

/** Closes the given dynamically opened port.  The `open_port_handle'
    argument must be the same value that was passed to SshAppgwOpenCB
    earlier.  This has no effect if the port is not currently open.
    Closing a port also closes any connections (flows) created using
    that port. */
void ssh_appgw_close_port(SshAppgwContext ctx,
                          SshUInt32 open_port_handle);

typedef enum {

  /** A new connection is to be created and `ctx' holds the connection
      identification in `initiator_ip', `initiator_port',
      `responder_ip', `responder_port'.  The application gateway can
      redirect the connection to different destination by calling the
      ssh_appgw_redirect function with new responder IP address and
      port.  The redirect operation must be completed by calling the
      ssh_appgw_redirect function for the context even if the
      application gateway did not redirect the request.  After the
      redirect operation is completed, there will be a new call to the
      connection callback with the SSH_APPGW_NEW_INSTANCE action. */
  SSH_APPGW_REDIRECT,

  /** New application gateway configuration data is set for the
      service object applying this gateway for its traffic.  The field
      `service_id' in the `ctx' identifies the service that has
      updated its configuration data.  The update configuration data
      is in the `config_data' field of the `ctx' structure and it is
      `config_data_len' bytes long. */
  SSH_APPGW_UPDATE_CONFIG,

  /** The system is shutting down and the application gateway instance
      must terminate all its connections and unregister itself by
      calling ssh_appgw_unregister. */
  SSH_APPGW_SHUTDOWN,

  /** The `ctx' was just created and this is the first call for it.
      For UDP gateways this implies also that an UDP packet was
      received from initiator.

      The instance may be destroyed explicitly by calling
      ssh_appgw_done, or by the system when it loses connection with
      the packet processing component. The user_destructor function
      may be set in the appgw context to close any allocated streams
      and to free any allocated memory when destruction occurs for
      whatever reason. */
  SSH_APPGW_NEW_INSTANCE,

  /** A UDP packet was received from the initiator for an existing session. */
  SSH_APPGW_UDP_PACKET_FROM_INITIATOR,

  /** A UDP packet was received from the responder for an existing session. */
  SSH_APPGW_UDP_PACKET_FROM_RESPONDER,

  /** A flow associated with this appgw connection was torn down. The
      appgw should attempt to gracefully cease operation of the
      connection and remove any flows. */
  SSH_APPGW_FLOW_INVALID
} SshAppgwAction;

/** Callback function that is called whenever a new connection to an
    application gateway occurs, when a packet is received for an
    existing UDP gateway.  If the connection is a TCP connection, then
    ctx->initiator_stream is a TCP/IP stream (see sshtcp.h and
    sshstream.h) that can be used to communicate with the initiator,
    and ctx->responder_stream is a connection to the responder.  If
    the appligation gateway is an UDP gateway, then `udp_data' will be
    the received packet; the application gateway is responsible for
    freeing it with ssh_xfree when it no longer needs it (it may keep
    the packet around for some time, if desired).  `udp_data' will be
    NULL if the connection is a TCP connection. */
typedef void (*SshAppgwConnCB)(SshAppgwContext ctx,
                               SshAppgwAction action,
                               const unsigned char *udp_data,
                               size_t udp_len,
                               void *context);

/** Error codes for appgw registration. */
typedef enum {
  SSH_APPGW_ERROR_OK            = 0, /** Registration successful. */
  SSH_APPGW_ERROR_TOOMANY       = 1, /** Too many appgws registered. */
  SSH_APPGW_ERROR_NOTFOUND      = 2, /** Required information not found. */
  SSH_APPGW_ERROR_VERSION       = 3, /** Version mismatch. */
  SSH_APPGW_ERROR_PROTOVERSION  = 4, /** Protocol version mismatch. */
  SSH_APPGW_ERROR_FAILED        = 5  /** Registration failed. */
} SshAppgwError;

/** Callback function that is called when the registration operation
    completes.  If the registration was successful, then `error' is
    SSH_APPGW_ERROR_OK; otherwise it indicates the cause of the
    failure. */
typedef void (*SshAppgwRegCB)(SshAppgwError error, void *context);

/** Flags for application gateway registration. */

/** Call connection callback with SSH_APPGW_REDIRECT allowing appgw to
    redirect new session to another destination */

#define SSH_APPGW_F_REDIRECT        0x00000001

/** If a PORT NAT is made for the appgw flows based on the Appgw trigger
    rule, then keep the initiator source port the same. */

#define SSH_APPGW_F_NAT_KEEP_PORT   0x00000002
/** If a PORT NAT is made for the appgw flows based on the Appgw trigger
    rule, then allow several flows to map to the same
    [source ip]:[source port] pair after port NAT. This flag does
    not require that SSH_APPGW_F_NAT_KEEP_PORT is set, but it is
    not really useful without it. */

#define SSH_APPGW_F_NAT_SHARE_PORT  0x00000004

/** Registers a local application gateway for TCP or UDP.  The
    argument `pm' is the policy manager controlling the firewall
    gateway.  SshAppgwParams is a pointer to a SshAppgwParams
    structure, which must be defined. The 'params->ident' field must
    be defined and should be a unique string identifying the gateway.
    The params->version and params->ipproto field must also have
    defined and meaningful values.  maximum length is
    SSH_APPGW_MAX_IDENT_LEN bytes.  `conn_callback' is a function to
    be called whenever a connection using the application gateway is
    created.  This will call `callback' either during this call or at
    some later time to indicate whether the gateway was successfully
    registered. */
void ssh_appgw_register_local(SshPm pm,
                              SshAppgwParams params,
                              SshUInt32 flags,
                              SshAppgwConnCB conn_callback,
                              void *conn_context,
                              SshAppgwRegCB callback, void *context);

/** Unregisters a local application gateway.  The argument `pm' is the
   policy manager controlling the firewall gateway.  The arguments
   `ident', `version', and `ipproto' are a for
   ssh_appgw_register_local. This function can only be called
   if all connections through the appgw have been terminated. */
void ssh_appgw_unregister_local(SshPm pm, const char *ident, SshUInt32 version,
                                SshUInt8 ipproto);


























#endif /* APPGW_API_H */
