/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to TCP sockets.
*/

#ifndef SSHTCP_H
#define SSHTCP_H

#include "sshinet.h"
#include "sshstream.h"
#include "sshoperation.h"

/** TCP error type. */
typedef enum {
  /** The connection or lookup was successful. */
  SSH_TCP_OK = 0,

  /** A new connection has been received - this result code is only
      given to listeners. */
  SSH_TCP_NEW_CONNECTION,

  /** No address could be found the host. */
  SSH_TCP_NO_ADDRESS,

  /** The address has no name. */
  SSH_TCP_NO_NAME,

  /** The destination is unreachable; this could indicate a routing
      problem, the host being off, or something similar. */
  SSH_TCP_UNREACHABLE,

  /** The destination refused the connection (for example, is not
      listening on the specified port). */
  SSH_TCP_REFUSED,

  /** A timeout occurred - this could indicate a network problem. */
  SSH_TCP_TIMEOUT,

  /** An operation has failed - this is a catch-all error used when
     none of the other codes is appropriate. */
  SSH_TCP_FAILURE
} SshTcpError;

/** Enum to define different ways to make the port and address
    reusable. */
typedef enum {
  SSH_TCP_REUSABLE_ADDRESS = 0, /** Address is reusable if the port is
                                    different (the default). */
  SSH_TCP_REUSABLE_PORT,        /** Port is reusable if the address is
                                    different. */
  SSH_TCP_REUSABLE_BOTH,        /** Both port and address are reusable. */
  SSH_TCP_REUSABLE_NONE         /** Port and address are not reusable. */
} SshTcpReusableType;

/** SOCKS type. */
typedef enum {
  SSH_TCP_SOCKS4 = 0, /** Use SOCKS4... */
  SSH_TCP_SOCKS5      /** or SOCKS5. */
} SshTcpSocksType;

/** Convert TCP error to string */
const char *ssh_tcp_error_string(SshTcpError error);

/** Callback function for socket creation.  The given function is
    called when a connection is ready. */
typedef void (*SshTcpCallback)(SshTcpError error,
                               SshStream stream,
                               void *context);

typedef struct SshTcpConnectParamsRec
*SshTcpConnectParams, SshTcpConnectParamsStruct;

/* Methods for TCP connect. These methods can be used to override the
   default platform specific implementations. */
typedef struct SshTcpConnectMethodsRec
{
  /* Connect a TCP stream. */
  SshOperationHandle (*connect_str)(void *connect_method_context,
                                    const unsigned char *local_address,
                                    unsigned int local_port,
                                    SshTcpReusableType local_reusable,
                                    const unsigned char *address_list,
                                    unsigned int port,
                                    int interface_index,
                                    int routing_instance_id,
                                    const SshTcpConnectParams params,
                                    SshTcpCallback callback,
                                    void *context);

  SshOperationHandle (*connect_ip)(void *connect_method_context,
                                   SshIpAddr remote_address,
                                   SshUInt16 remote_port,
                                   SshIpAddr local_address,
                                   SshUInt16 local_port,
                                   int interface_index,
                                   int routing_instance_id,
                                   const SshTcpConnectParams params,
                                   SshTcpCallback callback,
                                   void *context);

  Boolean (*has_ip_options)(SshStream stream);

  Boolean (*get_ip_addresses)(SshStream stream,
                              SshIpAddr local_ip,
                              SshUInt16 *local_port,
                              SshIpAddr remote_ip,
                              SshUInt16 *remote_port);

  Boolean (*set_nodelay)(SshStream stream,
                         Boolean on);

  Boolean (*set_keepalive)(SshStream stream,
                           Boolean on);

  Boolean (*set_linger)(SshStream stream,
                        Boolean on);

} SshTcpConnectMethodsStruct, *SshTcpConnectMethods;

/* Parameters to the ssh_tcp_connect function. To get default values
   just memset the structure before giving it the the ssh_tcp_connect
   function. */
struct SshTcpConnectParamsRec {
  /* Socks server url for going out through firewalls. URL specifies
     the SOCKS host, port, username, and socks network exceptions. If
     this is NULL or empty, the connection will be made without
     SOCKS. If port is not given in the url, the default SOCKS port
     (1080) will be used.  */
  unsigned char *socks_server_url;

  SshTcpSocksType socks_type;

 /** Number of connection attempts before giving up (some systems
     appear to spuriously fail connections without apparent reason,
     and retrying usually succeeds in those cases) - if this is zero
     then the default value of 1 is used. */
  SshUInt32 connection_attempts;

 /** Total timeout in seconds for the whole connection attempt - if
     the connection is not established before this timeout expires
     then the connect operation fails; if this is zero, then we
     use the timeouts defined by the operating system. */
  SshUInt32 connection_timeout;

  /** Use given protocol(s) to make connection (default value is zero,
      which means that any protocol can be used) - to limit protocols,
      SSH_IP_TYPE_MASK_IP4 or SSH_IP_TYPE_MASK_IP6 or bitwise or
      arbitrary 'bitwise or' of the SSH_IP_TYPE_MASK_* can be
      specified. */
  SshUInt32 protocol_mask;

  /** The local address to use in the connect operation - if
      this has the value NULL, the socket is not bind to local
      address; the system will select an unpriviledged port for the
      local socket. */
  const unsigned char *local_address;

  /** The local port to use in the connect operation - if
      this has the value NULL, the socket is not bind to local
      address; the system will select an unpriviledged port for the
      local socket. */
  const unsigned char *local_port_or_service;

  /** How the local address is reusable. */
  SshTcpReusableType local_reusable;

  /* Optional methods for TCP connect implementation. If these are unset,
     the platform specific TCP connect implementation will be used. */
  SshTcpConnectMethods tcp_connect_methods;

  /* Context data for tcp_connect_methods. */
  void *tcp_connect_methods_context;

};

/** Opens a connection to the specified host, and calls the callback
    when the connection has been established or has failed.  If
    connecting is successful, the callback will be called with error
    set to SSH_TCP_OK and an SshStream object for the connection
    passed in in the stream argument.  Otherwise, error will indicate
    the reason for the connection failing, and the stream will be
    NULL.

    Note that the callback may be called either during this call or
    some time later.

    @param host_name_or_address
    May be a numeric IP address or a host name (domain name), in
    which case it is looked up from the name servers.

    @param interface_index
    Interface index for the connection or -1 if not used.

    @param routing_instance_id
    Routing instance id for the connection.

    @param params
    The params structure can either be NULL or memset to zero to get
    default parameters. All data inside the params is copied during
    this call, so it can be freed immediately when this function
    returns.

    @return
    Returns SshOperationHandle that can be used to abort the TCP open.

   */
SshOperationHandle ssh_tcp_connect(const unsigned char *host_name_or_address,
                                   const unsigned char *port_or_service,
                                   int interface_index,
                                   int routing_instance_id,
                                   const SshTcpConnectParams params,
                                   SshTcpCallback callback,
                                   void *context);


SshOperationHandle ssh_tcp_connect_str(const unsigned char *local_address,
                                       unsigned int local_port,
                                       SshTcpReusableType local_reusable,
                                       const unsigned char *address_list,
                                       unsigned int port,
                                       int interface_index,
                                       int routing_instance_id,
                                       const SshTcpConnectParams params,
                                       SshTcpCallback callback,
                                       void *context);

/* Opens a connection to a specified IP address calling the
   callback when the connection has been established or
   failed. If connecting is successful, the callback will be
   called with error set to SSH_TCP_OK and an SshStream
   object for the connection passed in in the stream
   argument. Otherwise, error will indicate the reason for
   the connection failing, and the stream will be NULL.

   Note that the callback may be called either during this
   call or some time later.

   Returns SshOperationHandle that can be used to abort the
   tcp open.

   The connection is locally bound to the local_address and
   local_port if they are non NULL and non zero.

   The params structure can either be NULL or memset to zero
   to get default parameters. All data inside the params is
   copied during this call, so it can be freed immediately
   when this function returns. Some fields of the params
   struct are ignored when using this function. Ignored
   fields are all socks related fields, protocol_mask (it
   can be seen from the IP-address), local_address,
   local_port_or_service (taken from argument list),
   connection_attempts and connection_timeout. */

SshOperationHandle
ssh_tcp_connect_ip(SshIpAddr remote_address,
                   SshUInt16 remote_port,
                   SshIpAddr local_address,
                   SshUInt16 local_port,
                   int interface_index,
                   int routing_instance_id,
                   const SshTcpConnectParams params,
                   SshTcpCallback callback,
                   void *context);

/* **************** Function for listening for connections ******************/

typedef struct SshTcpListenerRec *SshTcpListener;

typedef struct SshTcpListenerParamsRec
SshTcpListenerParamsStruct, *SshTcpListenerParams;

typedef struct SshTcpListenerMethodsRec
{
  /* Create a new TCP listener. */
  void * (*make_tcp_listener)(void *listener_method_context,
                              const unsigned char *local_address,
                              const unsigned char *port_or_service,
                              int interface_index,
                              int routing_instance_id,
                              const SshTcpListenerParams params,
                              SshTcpCallback callback,
                              void *context);

  void * (*make_tcp_listener_ip)(void *listener_method_context,
                                 SshIpAddr local_address,
                                 SshUInt16 local_port,
                                 int interface_index,
                                 int routing_instance_id,
                                 const SshTcpListenerParams params,
                                 SshTcpCallback callback,
                                 void *context);

  /* Get local port number for listener. */
  SshUInt16 (*get_tcp_local_port_number)(void *listener_method_context,
                                         void *listener_context);

  /* Destroy listener. */
  void (*destroy_tcp_listener)(void *listener_method_context,
                               void *listener_context);

} SshTcpListenerMethodsStruct, *SshTcpListenerMethods;


/* Parameters to the ssh_tcp_make_listener function. To get default
   values just memset the structure before giving it the the
   ssh_tcp_make_listener function. */
struct SshTcpListenerParamsRec {
  SshTcpReusableType listener_reusable; /* How is it reusable. */
  int listen_backlog; /* Listen backlog size for the listener socket. */
  size_t send_buffer_size;      /* Send buffer size in bytes. */
  size_t receive_buffer_size;   /* Receive buffer size in bytes. */

  /* Optional methods for TCP listener implementation. If these are unset,
     the platform specific TCP listener implementation will be used. */
  SshTcpListenerMethods tcp_listener_methods;

  /* Context data for tcp_listenener_methods. */
  void *tcp_listener_methods_context;
};

/** Creates a socket that listens for new connections.  The address
    must be an ip-address in the form "nnn.nnn.nnn.nnn".
    SSH_IPADDR_ANY indicates any host; otherwise it should be the
    address of some interface on the system.

    @param interface_index
    Interface index for TCP listener or -1 if not used.

    @param routing_instance_id
    Routing instance id for TCP listener.

    @param params
    If the params is NULL or if it is memset to zero then default
    values for each parameter is used.

    @param callback
    The given callback will be called whenever a new connection is
    received at the socket.

    @return
    This returns NULL on error.

    */
SshTcpListener
ssh_tcp_make_listener(const unsigned char *local_address,
                      const unsigned char *port_or_service,
                      int interface_index,
                      int routing_instance_id,
                      const SshTcpListenerParams params,
                      SshTcpCallback callback,
                      void *context);

/** Make TCP listener using IP addresses. The IP Address should be either
    NULL meaning any ip address, or IP address of some interface on the
    system.

    @param local_port
    Local_port of zero means any port.

    @param interface_index
    Interface index for TCP listener or -1 if not used.

    @param routing_instance_id
    Routing instance id for TCP listener.

    @param params
    If the params is NULL or if it is memset to zero then default
    values for each parameter is used.

    @param callback
    The given callback will be called whenever a new
    connection is received at the socket.

    @return
    This returns NULL on error.

    */

SshTcpListener
ssh_tcp_make_listener_ip(SshIpAddr local_address,
                         SshUInt16 local_port,
                         int interface_index,
                         int routiting_instance_id,
                         const SshTcpListenerParams params,
                         SshTcpCallback callback,
                         void *context);

/** Fill in the buffer with the local port. This can be used if local port in
    the make lister was zero or NULL, meaning any port.

    @return
    This returns FALSE if the buffer is too small.

    */
Boolean ssh_tcp_listener_get_local_port(SshTcpListener listener,
                                        unsigned char *buf,
                                        size_t buflen);

/** Returns the local port used by the TCP listener. This can be used if local
    port in the make lister was zero or NULL, meaning any port.  */
SshUInt16 ssh_tcp_listener_get_local_port_number(SshTcpListener listener);

/** Destroys the socket.  It is safe to call this from a callback.
    If the listener was local, and a socket was created in the file
    system, this does not automatically remove the socket (so that it
    is possible to close the other copy after a fork).  The
    application should call remove() for the socket path when no
    longer needed.

    */
void ssh_tcp_destroy_listener(SshTcpListener listener);

/** Returns true (non-zero) if the socket behind the stream has IP
    options set.

    @return
    This returns FALSE if the stream is not a socket stream. */
Boolean ssh_tcp_has_ip_options(SshStream stream);

/** Returns the ip-address of the remote host, as string.

    @return
    This returns FALSE if the stream is not a socket stream or buffer
    space is insufficient.

    */
Boolean ssh_tcp_get_remote_address(SshStream stream, unsigned char *buf,
                                   size_t buflen);

/** Returns the remote port number, as a string.

    @return
    This returns FALSE if the stream is not a socket stream or buffer
    space is insufficient.

    */
Boolean ssh_tcp_get_remote_port(SshStream stream, unsigned char *buf,
                                size_t buflen);

/** Returns the ip-address of the local host, as string.

    @return
    This returns FALSE if the stream is not a socket stream or buffer
    space is insufficient.

   */
Boolean ssh_tcp_get_local_address(SshStream stream, unsigned char *buf,
                                  size_t buflen);

/* Returns the local port number, as a string.

   @return
   This returns FALSE if the stream is not a socket stream or buffer
   space is insufficient.

   */
Boolean ssh_tcp_get_local_port(SshStream stream, unsigned char *buf,
                               size_t buflen);

/** Returns the local and remove ip and port numbers. Any of the fields can be
    NULL, in which case it is not filled.

    @return
    Returns FALSE if the stream is not a socket stream.

   */
Boolean ssh_tcp_get_ip_addresses(SshStream stream,
                                 SshIpAddr local_ip,
                                 SshUInt16 *local_port,
                                 SshIpAddr remote_ip,
                                 SshUInt16 *remote_port);

/* ********************* Functions for socket options ***********************/

/** Sets/resets TCP options TCP_NODELAY for the socket.

    @return
    This returns TRUE on success.

    */
Boolean ssh_tcp_set_nodelay(SshStream stream, Boolean on);

/** Sets/resets socket options SO_KEEPALIVE for the socket.

    @return
    This returns TRUE on success.

    */
Boolean ssh_tcp_set_keepalive(SshStream stream, Boolean on);

/** Sets/resets socket options SO_LINGER for the socket.

    @return
    This returns TRUE on success.

    */
Boolean ssh_tcp_set_linger(SshStream stream, Boolean on);


#define SSH_INET_TCP_ACCESS_DELAY 30

typedef int
SshInetAccessRequestCallback(
        void *param,
        SshIpAddr local_address,
        SshIpAddr remote_address,
        int in_protocol,
        int local_port,
        int remote_port);

typedef void
SshInetAccessReleaseCallback(
        void *param,
        int handle,
        int delay_seconds);

void
ssh_inet_access_callbacks_set(
        SshInetAccessRequestCallback *request_func,
        SshInetAccessReleaseCallback *release_func,
        void *param);


int
ssh_inet_make_access_request_callback(
        SshIpAddr local_address,
        SshIpAddr remote_address,
        int in_protocol,
        int local_port,
        int remote_port);


void
ssh_inet_make_access_release_callback(
        int handle,
        int delay_seconds);


typedef int
SshTcpSocketRequestCallback(
        void *param,
        Boolean ip6);

typedef int
SshTcpSocketReleaseCallback(
        void *param,
        int sock);

void
ssh_tcp_socket_callbacks_set(
        SshTcpSocketRequestCallback *request_func,
        SshTcpSocketReleaseCallback *release_func,
        void *param);


int
ssh_tcp_make_socket_request_callback(
        Boolean ip6);


int
ssh_tcp_make_socket_release_callback(
        int socket);

#endif /* SSHTCP_H */
