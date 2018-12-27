/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows implementation of SSH TCP communication API.
*/

/*---------------------------------------------------------------------------
  INCLUDES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "sshstream.h"
#include "sshnameserver.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshwinutil2.h"

#include <iphlpapi.h>

/*---------------------------------------------------------------------------
  DEFINES
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshNetTcp"

/* IPv6 numbers are not there with Win 2k compatible build */
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif /* IPPROTO_IPV6 */

/*---------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/* TCP connection/TCP listener descriptor */
typedef struct SshTcpPlatformListenerRec
SshTcpPlatformListenerStruct, *SshTcpPlatformListener;

struct SshTcpPlatformListenerRec
{
  SOCKET sock;

  SshSockAddrStruct remote;
  SshSockAddrStruct local;

  SshTcpCallback cb;
  void *context;
  SshOperationHandle oper_handle;
  SshTcpPlatformListener next;
};

typedef struct SshTcpPlatformListenerRec
SshTcpConnectionStruct, *SshTcpConnection;

/* Stream descriptor utilizing Windows Socket */
typedef struct SshSocketStreamRec
{
  SOCKET sock;
  unsigned char close_on_destroy:1;
  unsigned char disconnected:1;
  unsigned char destroyed:1;
  unsigned char read_has_failed:1;
  unsigned char write_has_failed:1;

  /* Stream callback and single input argument for it */
  SshStreamCallback cb;
  void *context;
} SshSocketStreamStruct, *SshSocketStream;

/*---------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

/* Aborts TCP connection */
static void
ssh_tcp_connect_abort(void *context);

/* Creates listener to monitor inbound TCP connections */
static SshTcpPlatformListener
ssh_tcp_create_listener(SshIpAddr addr,
                        SshUInt16 port,
                        int interface_index,
                        int routing_instance_id,
                        const SshTcpListenerParams params,
                        SshTcpCallback cb,
                        VOID *ctx);

/* Tries to open a new outbound TCP connection */
static SshOperationHandle
ssh_tcp_create_connection(SshIpAddr local_addr,
                          SshUInt16 local_port,
                          SshTcpReusableType local_reusable,
                          SshIpAddr remote_addr,
                          SshUInt16 remote_port,
                          int interface_index,
                          int routing_instance_id,
                          SshTcpCallback callback,
                          void *context);

/* Recompute and set event loop request masks for the file descriptors. */
static void
ssh_socket_stream_set_request(SshSocketStream stream);

/* Event loop callback function for TCP socket read/write/close events */
static void
ssh_socket_stream_io_cb(unsigned int event,
                        void *context);

/* SSH Socket Stream constructor */
static SshStream
ssh_socket_stream_create(SOCKET sock,
                         Boolean close_on_destroy);

/* Reads data into buffer from SSH Socket Stream */
static int
ssh_socket_stream_read(void *context,
                       unsigned char *buf,
                       size_t size);

/* Writes data from buffer into a given SSH Socket Stream */
static int
ssh_socket_stream_write(void *context,
                        const unsigned char *buf,
                        size_t size);

/* Starts disconnect procedure on a given SSH Socket Stream */
static void
ssh_socket_stream_output_eof(void *context);

/* Sets callbacks for SSH Socket stream */
static void
ssh_socket_stream_set_stream_callback(void *context,
                                      SshStreamCallback cb,
                                      void *cb_context);

/* SSH Socket stream destructor */
static void
ssh_socket_stream_destroy(void *context);

/* Returns the socket associated into a given SSH Stream */
static SOCKET
ssh_socket_stream_get_socket(SshStream stream);

/* Method table for Windows TCP stream */
static const SshStreamMethodsStruct ssh_socket_method_table =
{
  ssh_socket_stream_read,
  ssh_socket_stream_write,
  ssh_socket_stream_output_eof,
  ssh_socket_stream_set_stream_callback,
  ssh_socket_stream_destroy
};

SshTcpConnectMethods
ssh_tcp_connect_platform_methods(void **constructor_context_return);

/*---------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  SSH_SOCKET_... API FUNCTIONS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Connects to the given remote address/port, and makes a stream for it.
  The address to use is the first address from the list.
  --------------------------------------------------------------------------*/
SshOperationHandle
ssh_socket_low_connect(void *connect_method_context,
                       const unsigned char *local_addr,
                       unsigned int local_port,
                       SshTcpReusableType local_reusable,
                       const unsigned char *addr_list,
                       unsigned int port,
                       int interface_index,
                       int routing_instance_id,
                       const SshTcpConnectParams params,
                       SshTcpCallback callback,
                       void *context)
{
  SshIpAddrStruct local_ip;
  SshIpAddrStruct remote_ip;
  __int64 first_len;
  unsigned char *tmp = NULL;

  /* Compute the length of the first address on the list. */
  if (ssh_ustrchr(addr_list, ','))
    first_len = ssh_ustrchr(addr_list, ',') - addr_list;
  else
    first_len = ssh_ustrlen(addr_list);

  SSH_ASSERT(first_len <= 0xFFFFFFFF); /* Win64 */

  tmp = ssh_memdup(addr_list, (unsigned int)first_len);

  if (!tmp || !ssh_ipaddr_parse(&remote_ip, tmp))
    {
      if (tmp)
        ssh_free(tmp);
      (*callback)(SSH_TCP_NO_ADDRESS, NULL, context);
      return NULL;
    }

  ssh_free(tmp);

  if (local_addr)
    {
      if (!ssh_ipaddr_parse(&local_ip, local_addr))
        {
          (*callback)(SSH_TCP_NO_ADDRESS, NULL, context);
          return NULL;
        }
    }
  else
    {
#if defined (WITH_IPV6)
      if (SSH_IP_IS6(&remote_ip))
        ssh_ipaddr_parse(&local_ip, SSH_IPADDR_ANY_IPV6);
      else
#endif /* WITH_IPV6 */
        ssh_ipaddr_parse(&local_ip, SSH_IPADDR_ANY_IPV4);
    }

  return (ssh_tcp_create_connection(&local_ip, (SshUInt16)local_port,
                                    local_reusable,
                                    &remote_ip, (SshUInt16)port,
                                    interface_index,
                                    routing_instance_id,
                                    callback, context));
}


SshOperationHandle
ssh_tcp_low_connect_ip(void *connect_method_context,
                       SshIpAddr remote_address,
                       SshUInt16 remote_port,
                       SshIpAddr local_address,
                       SshUInt16 local_port,
                       int interface_index,
                       int routing_instance_id,
                       const SshTcpConnectParams params,
                       SshTcpCallback callback,
                       void *context)
{
  SshTcpReusableType local_reusable = SSH_TCP_REUSABLE_NONE;

  if (params)
    local_reusable = params->local_reusable;

  return (ssh_tcp_create_connection(local_address, local_port,
                                    local_reusable,
                                    remote_address, remote_port,
                                    interface_index,
                                    routing_instance_id,
                                    callback, context));
}

/*---------------------------------------------------------------------------
  Creates a socket that listens for new inbound connections
  --------------------------------------------------------------------------*/
SshTcpPlatformListener
ssh_tcp_low_make_listener_ip(void *listener_method_context,
                             SshIpAddr local_address,
                             SshUInt16 local_port,
                             int interface_index,
                             int routing_instance_id,
                             const SshTcpListenerParams params,
                             SshTcpCallback callback,
                             void *context)
{
  SshTcpPlatformListener listener = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tcp_make_listener_ip()"));

  if (!local_address || !SSH_IP_DEFINED(local_address))
    {
      SshIpAddrStruct ipv4_any;
#if defined (WITH_IPV6)
      SshIpAddrStruct ipv6_any;

      ssh_ipaddr_parse(&ipv6_any, SSH_IPADDR_ANY_IPV6);
#endif /* WITH_IPV6 */
      ssh_ipaddr_parse(&ipv4_any, SSH_IPADDR_ANY_IPV4);

      /* Create IPv4 listener */
      listener = ssh_tcp_create_listener(&ipv4_any, local_port,
                                         interface_index,
                                         routing_instance_id,
                                         params, callback, context);
#if defined (WITH_IPV6)
      if (listener)
        /* Create auxiliary IPv6 listener */
        listener->next = ssh_tcp_create_listener(&ipv6_any, local_port,
                                                 interface_index,
                                                 routing_instance_id,
                                                 params, callback, context);
      else
        /* Create only IPv6 listener */
        listener = ssh_tcp_create_listener(&ipv6_any, local_port,
                                           interface_index,
                                           routing_instance_id,
                                           params, callback, context);
#endif /* WITH_IPV6 */
    }
  else
    {
      /* Create either IPv4 or IPv6 listener */
      listener = ssh_tcp_create_listener(local_address, local_port,
                                         interface_index,
                                         routing_instance_id,
                                         params, callback, context);
    }

  return (listener);
}


SshTcpPlatformListener
ssh_tcp_low_make_listener(void *listener_method_context,
                          const unsigned char *local_addr,
                          const unsigned char *port_or_service,
                          int interface_index,
                          int routing_instance_id,
                          const SshTcpListenerParams params,
                          SshTcpCallback callback,
                          void *context)
{
  SshIpAddrStruct ip;
  SshIpAddr local_ip = NULL;
  unsigned int local_port;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tcp_make_listener()"));

  local_port = ssh_inet_get_port_by_service(port_or_service, "tcp");

  if (local_port == (unsigned int)-1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get TCP port number!"));
      return NULL;
    }

  if (local_addr && !SSH_IS_IPADDR_ANY(local_addr))
    {
      if (!ssh_ipaddr_parse(&ip, local_addr))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to parse IP address!"));
          return NULL;
        }

      local_ip = &ip;
    }

  return (ssh_tcp_low_make_listener_ip(listener_method_context,
                                       local_ip, (SshUInt16)local_port,
                                       interface_index,
                                       routing_instance_id,
                                       params, callback, context));
}


/*---------------------------------------------------------------------------
  Destroys the SSH TCP listener and closes the associated socket
  --------------------------------------------------------------------------*/
void
ssh_tcp_low_destroy_listener(void *listener_method_context,
                             void *listener_context)
{
  SshTcpPlatformListener listener = listener_context;

  if (!listener)
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_destroy_listener()"));

  /* Destroy any sibling listener */
  if (listener->next)
    ssh_tcp_low_destroy_listener(listener_method_context, listener->next);

  /* Unregister socket from the event loop */
  ssh_io_unregister_fd(listener->sock, FALSE);

  /* Close socket */
  closesocket(listener->sock);

  /* Free listener context */
  ssh_free(listener);
}


/*---------------------------------------------------------------------------
  Checks if the socket associated with the stream has IP options set.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_has_ip_options(SshStream stream)
{
  INT err = 0;
  INT opt_size = 8192;
  UCHAR *opt = NULL;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  opt = ssh_calloc(1, opt_size);
  if (opt == NULL)
    return (FALSE);

  err = getsockopt(sock, IPPROTO_IP, IP_OPTIONS, opt, &opt_size);

#if defined (WITH_IPV6)
  if (err)
    err = getsockopt(sock, IPPROTO_IPV6, IP_OPTIONS, opt, &opt_size);
#endif /* WITH_IPV6 */

  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW, WSAGetLastError());

  ssh_free(opt);

  return (!err && (opt_size > 0));
}

#if 0
/*---------------------------------------------------------------------------
  Retrieves the IP address of the remote host, as string.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_get_remote_address(SshStream stream,
                               unsigned char *buf,
                               size_t buf_len)
{
  SshSockAddrStruct ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SOCKADDR *sa = (SOCKADDR *) &ss;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  memset(&ss, 0, sa_len);

  if (getpeername(sock, sa, &sa_len) == SOCKET_ERROR)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
      return (FALSE);
    }

  return (ssh_socket_address_get_ipaddr(sa, buf, buf_len));
}

/*---------------------------------------------------------------------------
  Retrieves the port number of the remote host, as string.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_get_remote_port(SshStream stream,
                            unsigned char *buf,
                            size_t buf_len)
{
  SshSockAddrStruct ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SOCKADDR *sa = (SOCKADDR *) &ss;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  if (getpeername(sock, sa, &sa_len) == SOCKET_ERROR)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
      return (FALSE);
    }

  return (ssh_socket_address_get_port(sa, buf, buf_len));
}

/*---------------------------------------------------------------------------
  Retrieves the IP address of the local host, as string.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_get_local_address(SshStream stream,
                              unsigned char *buf,
                              size_t buf_len)
{
  SshSockAddrStruct ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SOCKADDR *sa = (SOCKADDR *) &ss;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  if (getsockname(sock, sa, &sa_len) == SOCKET_ERROR)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

      return (FALSE);
    }

  return (ssh_socket_address_get_ipaddr(sa, buf, buf_len));
}

/*---------------------------------------------------------------------------
  Retrieves the port number of the local host, as string.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_get_local_port(SshStream stream,
                           unsigned char *buf,
                           size_t buf_len)
{
  SshSockAddrStruct ss;
  SOCKADDR *sa = (SOCKADDR *) &ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  if (getsockname(sock, sa, &sa_len) == SOCKET_ERROR)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
      return (FALSE);
    }

  return (ssh_socket_address_get_port(sa, buf, buf_len));
}
#endif /* 0 */

/*---------------------------------------------------------------------------
  Retrieves the port number of the local host, as unsigned integer.
  --------------------------------------------------------------------------*/
SshUInt16
ssh_tcp_low_listener_get_local_port_number(void *listener_method_context,
                                           void *listener_context)
{
  SshTcpPlatformListener listener = listener_context;
  SshSockAddrStruct ss;
  SOCKADDR *sa = (SOCKADDR *) &ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SshUInt16 port = 0;

  if (listener->sock == INVALID_SOCKET)
    return (0);

  if (getsockname(listener->sock, sa, &sa_len) == SOCKET_ERROR)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
      return (0);
    }

  ssh_socket_address_get_port_value(sa, &port);
  return (port);
}

/*---------------------------------------------------------------------------
  Retrieves the IP addresses and port numbers of the local and remote hosts.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_get_ip_addresses(SshStream stream,
                             SshIpAddr local_ip,
                             SshUInt16 *local_port,
                             SshIpAddr remote_ip,
                             SshUInt16 *remote_port)
{
  SshSockAddrStruct ss;
  SOCKADDR *sa = (SOCKADDR *) &ss;
  INT sa_len = sizeof(SshSockAddrStruct);
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  if (local_ip || local_port)
    {
      memset(sa, 0, sa_len);
      if (getsockname(sock, sa, &sa_len) == SOCKET_ERROR)
        {
          ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
          return (FALSE);
        }

      if (local_ip
          && ssh_socket_address_get_ip(sa, local_ip) == FALSE)
        return FALSE;

      if (local_port
          && ssh_socket_address_get_port_value(sa, local_port) == FALSE)
        return FALSE;
    }

  if (remote_ip || remote_port)
    {
      memset(sa, 0, sa_len);
      if (getpeername(sock, sa, &sa_len) == SOCKET_ERROR)
        {
          ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());
          return (FALSE);
        }

      if (remote_ip
          && ssh_socket_address_get_ip(sa, remote_ip) == FALSE)
        return FALSE;

      if (remote_port
          && ssh_socket_address_get_port_value(sa, remote_port) == FALSE)
        return FALSE;
    }

  return TRUE;
}

/*---------------------------------------------------------------------------
  Sets/resets TCP options TCP_NODELAY for the socket.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_set_nodelay(SshStream stream,
                        Boolean on)
{
  INT val = (on == TRUE ? 1 : 0);
  INT err = 0;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  err = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&val, sizeof(val));
  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

  return (!err);
}


/*---------------------------------------------------------------------------
  Sets/resets TCP options TCP_KEEPALIVE for the socket.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_set_keepalive(SshStream stream,
                          Boolean on)
{
#if defined(SOL_SOCKET) && defined(SO_KEEPALIVE)
  INT val = (on == TRUE ? 1 : 0);
  INT err = 0;
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  err = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&val, sizeof(val));
  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

  return (!err);
#else /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
  return (FALSE);
#endif /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
}

/*---------------------------------------------------------------------------
  Sets/resets socket options SO_LINGER for the socket.
  --------------------------------------------------------------------------*/
Boolean
ssh_tcp_low_set_linger(SshStream stream,
                       Boolean on)
{
#if defined (SOL_SOCKET) && defined (SO_LINGER)
  INT err = 0;
  LINGER val = {(on ? 1 : 0), (on ? 15 : 0)};
  SOCKET sock = ssh_socket_stream_get_socket(stream);

  if (sock == INVALID_SOCKET)
    return (FALSE);

  err = setsockopt(sock, SOL_SOCKET, SO_LINGER, (VOID *)&val, sizeof(val));
  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

  return (!err);
#else /* defined (SOL_SOCKET) && defined (SO_LINGER) */
  return (FALSE);
#endif /* defined (SOL_SOCKET) && defined (SO_LINGER) */
}

/*---------------------------------------------------------------------------
  FUNCTIONS FOR NAME SERVER LOOKUPS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Gets the name of the host we are running on.  To get the corresponding IP
  address(es), a name server lookup must be done using the functions below.
  --------------------------------------------------------------------------*/
void
ssh_tcp_get_host_name(unsigned char *buf,
                      size_t buf_len)
{
  FIXED_INFO info;
  ULONG info_len = sizeof(info);

  /* NOTE: we can't use the 'obvious' solution gethostname(), because it
     doesn't necessarily return host name in FQDN format. */

  if (GetNetworkParams(&info, &info_len) == ERROR_SUCCESS)
    {
      if (strlen(info.DomainName))
        ssh_snprintf(buf, buf_len, "%s.%s", info.HostName, info.DomainName);
      else
        ssh_snprintf(buf, buf_len, "%s", info.HostName);

      return;
    }

  /* Unable to get host name */
  ssh_ustrncpy(buf, "UNKNOWN", buf_len);
}

/*---------------------------------------------------------------------------
  Looks up all ip-addresses of the host, returning them
  as a comma-separated list
  --------------------------------------------------------------------------*/
unsigned char *
ssh_tcp_get_host_addrs_by_name_sync(const unsigned char *name)
{
  CHAR *buf = NULL;
  DWORD i = 0;
  HOSTENT *he = NULL;
  int err = 0;

  if (!name)
    return (NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_tcp_get_host_addrs_by_name_sync(): Name[%s]", name));

  do
    {
      size_t buf_len = 0;
      ADDRINFO *ai = NULL, *aii = NULL;

      /* Try to get the addresses from the name server(s). */
      err = getaddrinfo(name, NULL, NULL, &ai);
      if (err)
        break;

      /* Iterate through addresses */
      for (aii = ai; aii != NULL; aii = ai->ai_next)
        {
          void *temp;
          INT len = 64;

          /* Allocate memory for new address */
          temp = ssh_realloc(buf, buf_len, buf_len + len + 1);
          if (temp == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
              continue;
            }
          buf = temp;

          if (!ssh_socket_address_get_ipaddr(aii->ai_addr,
                                             buf + buf_len, len))
            continue;

          /* Add comma separator */
          if (aii != ai)
            ssh_ustrcat(buf, ",");

          /* Advance buffer length */
          buf_len += strlen(buf);
        }

      freeaddrinfo(ai);
    }
  while (0);

  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, err);

  return (buf);
}


/*---------------------------------------------------------------------------
  Looks up the name of the host by its ip-address.  Verifies that the
  address returned by the name servers also has the original ip
  address.
  --------------------------------------------------------------------------*/
unsigned char *
ssh_tcp_get_host_by_addr_sync(const unsigned char *addr)
{
  SshIpAddrStruct ipaddr;
  CHAR *name = NULL;
  CHAR *ha = NULL;
  SshSockAddrStruct ss;
  SOCKADDR *sa;
  HOSTENT *he = NULL;
  DWORD name_len = NI_MAXHOST, serv_len = 0;
  INT sa_len = sizeof(SshSockAddrStruct);
  INT i = 0;
  INT err = 0;
  INT pf = PF_UNSPEC;

  if (!addr || !ssh_ipaddr_parse(&ipaddr, addr))
    return (NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_tcp_get_host_by_addr_sync(): Addr[%s]", addr));

  if (ssh_socket_address_create(&ipaddr, 0, &sa_len, &pf, &ss) == NULL)
    return (NULL);

  sa = (SOCKADDR *)&ss;

  name = ssh_calloc(1, name_len);
  if (!name)
    return (NULL);

  err = getnameinfo(sa, sa_len,
                    name, name_len,
                    NULL, serv_len,
                    NI_NAMEREQD | NI_NOFQDN);

  if (err)
    {
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, err);
      ssh_free(name);
      return (NULL);
    }

  /* We should have name now */

  /* Map it back to an IP address and check that the given address
     actually is an address of this host.  This is necessary because
     anyone with access to a name server can define arbitrary names
     for an IP address.  Mapping from name to IP address can be
     trusted better (but can still be fooled if the intruder has
     access to the name server of the domain). */

  /* Get addresses (comma-separated list) */
  ha = ssh_tcp_get_host_addrs_by_name_sync(name);
  if (!ha)
    {
      ssh_free(name);
      return (NULL);
    }

  /* Search for a given address from the list */
  if (!strstr(ha, addr))
    {
      ssh_free(ha);
      ssh_free(name);

      return (NULL);
    }

  /* Address was found for the host name.  We accept the host name. */
  ssh_free(ha);
  return (name);
}

/*---------------------------------------------------------------------------
  SSH_INET_... API FUNCTIONS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Looks up the service (port number) by name and protocol.
  --------------------------------------------------------------------------*/
int
ssh_inet_get_port_by_service(const unsigned char *name,
                             const unsigned char *proto)
{
  const unsigned char *cp = NULL;
  SERVENT *se = NULL;

  if (!name)
    return (-1);

  for (cp = name; isdigit(*cp); cp++);

  if (!*cp && *name)
    return (atoi(name));

  se = getservbyname(name, proto);
  if (!se)
    return (-1);

  return (ntohs(se->s_port));
}

/*---------------------------------------------------------------------------
  Looks up the name of the service based on port number and protocol.
  --------------------------------------------------------------------------*/
void
ssh_inet_get_service_by_port(unsigned int port,
                             const unsigned char *proto,
                             unsigned char *buf,
                             size_t buf_len)
{
  SERVENT *se = getservbyport(htons((USHORT) port), proto);

  if (!se)
    ssh_snprintf(buf, buf_len, "%u", port);
  else
    ssh_ustrncpy(buf, se->s_name, buf_len);
}

/*---------------------------------------------------------------------------
  Compares two port numbers
  --------------------------------------------------------------------------*/
int
ssh_inet_port_number_compare(const unsigned char *port1,
                             const unsigned char *port2,
                             const unsigned char *proto)
{
  INT nport1 = ssh_inet_get_port_by_service(port1, proto);
  INT nport2 = ssh_inet_get_port_by_service(port2, proto);

  if (nport1 == -1 || nport2 == -1)
    return (0);

  if (nport1 == nport2)
    return (0);

  if (nport1 < nport2)
    return (-1);

  return (1);
}

/*---------------------------------------------------------------------------
  SSH SECURE SHELL SPECIFIC FUNCTIONS
  --------------------------------------------------------------------------*/

/* These two functions were added to the Secure Shell NT Daemon project.
   It was decided that they should not be declared in the public header,
   as they are not platform independent, but instead they are declared
   in the application code and used directly. -tomi@ssh.com */

/*---------------------------------------------------------------------------
  Returns the Windows socket associated into a given SSH Stream
  --------------------------------------------------------------------------*/
SOCKET
ssh_socket_get_handle(SshStream stream)
{
  return (ssh_socket_stream_get_socket(stream));
}

/*---------------------------------------------------------------------------
  Creates a new SSH Stream utilizing given Windows socket
  --------------------------------------------------------------------------*/
SshStream
ssh_socket_wrap(SOCKET sock,
                Boolean close_on_destroy)
{
  return (ssh_socket_stream_create(sock, close_on_destroy));
}

/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static void
ssh_socket_set_send_buffer_size(SOCKET s,
                                size_t size)
{
#ifdef SO_SNDBUF
  int opt, len, err;

  opt = (int)size;
  len = sizeof(opt);

  SSH_ASSERT(size <= 0xFFFFFFFF);

  err = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (CHAR*) &opt, len);
  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW, WSAGetLastError());
#endif /* SO_SNDBUF */
}

static void
ssh_socket_set_recv_buffer_size(SOCKET s,
                                size_t size)
{
#ifdef SO_RCVBUF
  int opt, len, err;

  opt = (int)size;
  len = sizeof(opt);

  SSH_ASSERT(size <= 0xFFFFFFFF);

  err = setsockopt(s, SOL_SOCKET, SO_RCVBUF, (CHAR*) &opt, len);
  if (err)
    ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW, WSAGetLastError());
#endif /* SO_RCVBUF */
}

/*---------------------------------------------------------------------------
  Aborts a TCP connection.
  --------------------------------------------------------------------------*/
static void
ssh_tcp_connect_abort(void *context)
{
  SshTcpConnection c = (SshTcpConnection) context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tcp_connect_abort()"));

  if (c)
    {
      ssh_io_unregister_fd(c->sock, FALSE);
      closesocket(c->sock);

      ssh_free(c);
    }
}


/*---------------------------------------------------------------------------
  This event loop callback is called whenever a new connection is made to a
  listener socket.
  --------------------------------------------------------------------------*/
static void
ssh_tcp_listen_cb(unsigned int io_event,
                  void *context)
{
  int len = sizeof(SshSockAddrStruct);
  SshTcpPlatformListener listener = (SshTcpPlatformListener)context;
  SshStream stream;

  if (io_event & SSH_IO_WRITE)
    {
      SOCKET sock;

      /* New inbound connection. Accept connection and then create
         new SSH stream for new accepted connection. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_tcp_listen_cb(%ld): FD_ACCEPT", listener->sock));

      sock = accept(listener->sock, (SOCKADDR *)&listener->remote, &len);

      if (sock != INVALID_SOCKET)
        {
          /* Create new SSH stream for this connection */
          stream = ssh_socket_stream_create(sock, TRUE);
          ssh_stream_set_private_methods(stream,
                              (void *) ssh_tcp_connect_platform_methods(NULL));
          listener->cb(SSH_TCP_NEW_CONNECTION, stream, listener->context);
        }
      /* Re-enable accept requests on the listener */
      ssh_io_set_fd_request(listener->sock, FD_ACCEPT);
    }
}


static void
ssh_tcp_connect_cb(unsigned int io_event,
                   void *context)
{
  SshTcpConnection c = (SshTcpConnection) context;
  SshStream stream;

  ssh_io_unregister_fd(c->sock, FALSE);

  switch (io_event)
    {
    case SSH_IO_CLOSED:
      /* Outbound connect failed. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_tcp_connect_cb(%ld): Failed to connect", c->sock));
      c->cb(SSH_TCP_UNREACHABLE, NULL, c->context);
      break;

    default:
      /* Outbound connect succeeded. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_tcp_connect_cb(%ld): Connected", c->sock));

      stream = ssh_socket_stream_create(c->sock, TRUE);
      ssh_stream_set_private_methods(stream,
                              (void *) ssh_tcp_connect_platform_methods(NULL));

      c->cb(SSH_TCP_OK, stream, c->context);
      break;
    }

  if (c->oper_handle)
    ssh_operation_unregister(c->oper_handle);

  ssh_free(c);
}



/*---------------------------------------------------------------------------
  Constructor for listener type of TCP socket.
  --------------------------------------------------------------------------*/
static SshTcpPlatformListener
ssh_tcp_create_listener(SshIpAddr addr,
                        SshUInt16 port,
                        int interface_index,
                        int routing_instance_id,
                        const SshTcpListenerParams params,
                        SshTcpCallback cb,
                        void *ctx)
{
  INT err = 0, listen_backlog = 5, sa_len = 0, pf = PF_UNSPEC;
  SshTcpPlatformListener obj = ssh_calloc(1, sizeof(*obj));

  if (!obj)
    return (NULL);

  obj->cb = cb;
  obj->context = ctx;
  obj->next = NULL;
  obj->sock = INVALID_SOCKET;

  if (params && params->listen_backlog != 0)
    listen_backlog = params->listen_backlog;

  /* Create a socket address */
  if (ssh_socket_address_create(addr, port, &sa_len, &pf, &obj->local) == NULL)
    {
      ssh_free(obj);
      return (NULL);
    }

  do
    {
      /* Try to create a TCP socket. */
      obj->sock = socket(((SOCKADDR *)(&obj->local))->sa_family,
                         SOCK_STREAM, pf);
      if (obj->sock == INVALID_SOCKET)
        {
          err = SOCKET_ERROR;
          break;
        }

      /* Set socket params */
      if (!params)
        {
          /* We don't want to reuse address by default on Windows, because
            SO_REUSEADDR actually means both SO_REUSEADDR and SO_REUSEPORT on
            Windows, meaning also the port is reused. (SO_REUSEPORT is not
            available on Windows.) */

          /* ssh_socket_set_reuseaddr(sock); */
        }
      else
        {
          if (params->send_buffer_size > 0)
            ssh_socket_set_send_buffer_size(obj->sock,
                                            params->send_buffer_size);

          if (params->receive_buffer_size > 0)
            ssh_socket_set_recv_buffer_size(obj->sock,
                                            params->receive_buffer_size);

          switch (params->listener_reusable)
            {
            default:
              break;

            case SSH_TCP_REUSABLE_PORT:
              ssh_socket_set_reuseport(obj->sock);
              break;

            case SSH_TCP_REUSABLE_ADDRESS:
              ssh_socket_set_reuseaddr(obj->sock);
              break;

            case SSH_TCP_REUSABLE_BOTH:
              ssh_socket_set_reuseport(obj->sock);
              ssh_socket_set_reuseaddr(obj->sock);
              break;
            }
        }

      /* Try to bind the socket into a specified address */
      err = bind(obj->sock, (SOCKADDR *)&obj->local, sa_len);
      if (err) break;

      /* Set socket into listening mode */
      err = listen(obj->sock, listen_backlog);

      /* Register the new socket to accept inbound connections */
      ssh_io_register_fd(obj->sock, ssh_tcp_listen_cb, obj);
      ssh_io_set_fd_request(obj->sock, FD_ACCEPT);
    }
  while (0);

  if (err)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Create TCP listener failed: Local[%@:%d]",
                 ssh_ipaddr_render, addr, port));

      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

      if (obj && obj->sock != INVALID_SOCKET)
        closesocket(obj->sock);

      ssh_free(obj);

      return (NULL);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Create TCP listener succeeded: Local[%@:%d]",
             ssh_ipaddr_render, addr, port));

  return (obj);
}


/*---------------------------------------------------------------------------
  Connects to the given remote address/port, and makes a stream for it.
  The address to use is the first address from the list.
  --------------------------------------------------------------------------*/
static SshOperationHandle
ssh_tcp_create_connection(SshIpAddr local_addr,
                          SshUInt16 local_port,
                          SshTcpReusableType local_reusable,
                          SshIpAddr remote_addr,
                          SshUInt16 remote_port,
                          int interface_index,
                          int routing_instance_id,
                          SshTcpCallback callback,
                          void *context)
{
  SshTcpConnection c = NULL;
  SshTcpError err = SSH_TCP_OK;
  SshIpAddrStruct laddr_struct, *laddr;
  SshUInt16 lport;

  do
    {
      int la_len = 0;
      int ra_len = 0;
      int pf = PF_UNSPEC;

      if ((c = ssh_calloc(1, sizeof(*c))) == NULL)
        {
          err = SSH_TCP_FAILURE;
          break;
        }

      /* Fill connection information */
      c->sock = INVALID_SOCKET;
      c->cb = callback;
      c->context = context;
      c->oper_handle = NULL;

      /* Create remote socket addresses */
      if (ssh_socket_address_create(remote_addr, remote_port,
                                    &ra_len, &pf, &c->remote) == NULL)
        {
          err = SSH_TCP_FAILURE;
          break;
        }

      /* Try to create a TCP socket for this protocol family */
      c->sock = socket(((SOCKADDR *)(&c->remote))->sa_family, SOCK_STREAM, pf);
      if (c->sock == INVALID_SOCKET)
        {
          err = SSH_TCP_FAILURE;
          break;
        }

      switch (local_reusable)
        {
        default:
        case SSH_TCP_REUSABLE_NONE:
          break;

        case SSH_TCP_REUSABLE_PORT:
          ssh_socket_set_reuseport(c->sock);
          break;

        case SSH_TCP_REUSABLE_ADDRESS:
          ssh_socket_set_reuseaddr(c->sock);
          break;

        case SSH_TCP_REUSABLE_BOTH:
          ssh_socket_set_reuseport(c->sock);
          ssh_socket_set_reuseaddr(c->sock);
          break;
        }

      /* Replace wildcard local address with a specific one if
         necessary on this system (e.g. Windows Mobile). */
      if (remote_addr && SSH_IP_DEFINED(remote_addr) &&
          (!local_addr ||
           !SSH_IP_DEFINED(local_addr) ||
           SSH_IP_IS_NULLADDR(local_addr)) &&
          ssh_win32_select_local_address(&laddr_struct, remote_addr))
        {
          laddr = &laddr_struct;
          lport = 0;
        }
      else if (local_addr && SSH_IP_DEFINED(local_addr))
        {
          laddr = local_addr;
          lport = local_port;
        }
      else
        {
          laddr = NULL;
          lport = 0;
        }

      /* Bind local end if requested. */
      if (laddr)
        {
          if (ssh_socket_address_create(laddr, lport, &la_len, &pf,
                                        &c->local) == NULL)
            goto fail;

          err = bind(c->sock, (SOCKADDR *)&c->local, la_len);
          if (err == SOCKET_ERROR)
            {
            fail:
              err = SSH_TCP_FAILURE;
              break;
            }
        }

      /* Register new socket and request connect notifications */
      ssh_io_register_fd(c->sock, ssh_tcp_connect_cb, c);
      ssh_io_set_fd_request(c->sock, FD_CONNECT);

      /* Try to establish a connection into remote site */
      err = connect(c->sock, (SOCKADDR *)&c->remote, ra_len);
      if (err == 0)
        {
          /* Connect complete */
          ssh_tcp_connect_cb(FD_CONNECT, c);
          return NULL; /* done! */
        }

      if (err == SOCKET_ERROR)
        {
          err = WSAGetLastError();
          if (err == WSAEWOULDBLOCK)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("ssh_tcp_create_connection(%ld) pending", c->sock));

              /* Connection pending */
              c->oper_handle = ssh_operation_register(ssh_tcp_connect_abort,
                                                      c);
              err = SSH_TCP_OK;
            }
          else
            {
              /* Some error occured */
              err = SSH_TCP_FAILURE;
            }
        }
    } while (0);

  /* Error handling */
  if (err != SSH_TCP_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_tcp_create_connection(%ld) failed", c->sock));

      if (c && c->sock != INVALID_SOCKET)
        {
          /* Unregister socket from event loop */
          ssh_io_set_fd_request(c->sock, 0);
          ssh_io_unregister_fd(c->sock, FALSE);
          closesocket(c->sock);
        }

      if (c && c->oper_handle)
        ssh_operation_unregister(c->oper_handle);

      ssh_free(c);
      callback(err, NULL, context);

      return (NULL);
    }

  return (c->oper_handle);
}

/*---------------------------------------------------------------------------
  SSH_SOCKET_STREAM_...() API FUNCTIONS
  --------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Recompute and set event loop request masks for the file descriptors.
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_set_request(SshSocketStream stream)
{
  unsigned int events = 0;

  SSH_ASSERT(!stream->destroyed);

  if (!stream->disconnected)
    {
      events |= FD_CLOSE;

      if (stream->read_has_failed)
        events |= FD_READ;

      if (stream->write_has_failed)
        events |= FD_WRITE;
    }

  ssh_io_set_fd_request(stream->sock, events);
}


/*---------------------------------------------------------------------------
  Event loop callback function for socket stream read/write/close
  notifications.
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_io_cb(unsigned int io_event,
                        void *context)
{
  SshSocketStream stream = (SshSocketStream)context;

  if (io_event == SSH_IO_CLOSED)
    {
      /* Socket has been closed */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_socket_stream_io_cb(%ld): FD_CLOSE", stream->sock));

      stream->read_has_failed = 0;
      if (stream->cb && !stream->disconnected)
        {
          stream->cb(SSH_STREAM_INPUT_AVAILABLE, stream->context);
          stream->disconnected = TRUE;
        }
    }

  if (io_event & SSH_IO_READ)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_socket_stream_io_cb(%ld): FD_READ", stream->sock));

      stream->read_has_failed = 0;
      if (stream->cb && !stream->disconnected)
        stream->cb(SSH_STREAM_INPUT_AVAILABLE, stream->context);
    }

  if (io_event & SSH_IO_WRITE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_socket_stream_io_cb(%ld): FD_WRITE", stream->sock));

      stream->write_has_failed = 0;
      if (stream->cb && !stream->disconnected)
        stream->cb(SSH_STREAM_CAN_OUTPUT, stream->context);
    }

  /* Recompute the request masks.  Note that the context might have been
     destroyed by one of the earlier callbacks. */
  if (!stream->destroyed)
    ssh_socket_stream_set_request(stream);
}


/*---------------------------------------------------------------------------
  Creates a stream around a given Windows socket
  --------------------------------------------------------------------------*/
static SshStream
ssh_socket_stream_create(SOCKET sock,
                         Boolean close_on_destroy)
{
  SshStream stream = NULL;
  SshSocketStream sock_stream = NULL;

  if (sock == INVALID_SOCKET)
    return (NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_socket_stream_create(%ld)", sock));

  sock_stream = ssh_calloc(1, sizeof(*sock_stream));
  if (!sock_stream)
    return (NULL);

  sock_stream->sock = sock;
  sock_stream->close_on_destroy = (close_on_destroy == TRUE ? 1:0);
  sock_stream->disconnected = 0;
  sock_stream->destroyed = 0;
  sock_stream->read_has_failed = 0;
  sock_stream->write_has_failed = 0;

  stream = ssh_stream_create(&ssh_socket_method_table, sock_stream);
  if (stream)
    {
      ssh_io_register_fd(sock, ssh_socket_stream_io_cb, sock_stream);
      ssh_io_set_fd_request(sock, FD_CLOSE | FD_READ | FD_WRITE);
    }

  return (stream);
}

/*---------------------------------------------------------------------------
  Reads at most `size' bytes to the buffer `buffer' using the WinsockStream.
  --------------------------------------------------------------------------*/
static int
ssh_socket_stream_read(void *context,
                       unsigned char *buf,
                       size_t size)
{
  SshSocketStream stream = (SshSocketStream)context;
  int err = 0;
  ULONG len = 0;

  SSH_ASSERT(stream != NULL);
  SSH_ASSERT(!stream->destroyed);
  SSH_ASSERT(!stream->sock != INVALID_SOCKET);
  SSH_ASSERT(size <= 0xFFFFFFFF);

  /* Try to read data into buffer */
  err = recv(stream->sock, buf, (int)size, 0);

  if (err != SOCKET_ERROR)
    {
      /* Read succeeded */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_socket_stream_read(%ld): %ld",
                 stream->sock, err));
      return (err);
    }

  /* No data available, check the reason and return with possible error */
  err = WSAGetLastError();
  switch (err)
    {
    default:
      /* Some real network error */
      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW, err);
      stream->read_has_failed = 1;
      ssh_socket_stream_set_request(stream);
      err = 0;
      break;

    case WSAEWOULDBLOCK:
      /* No data available so re-enable FD_READ notifications */
      stream->read_has_failed = 1;
      ssh_socket_stream_set_request(stream);
      err = -1;
      break;

    case WSAEMSGSIZE:
      /* The supplied buffer was too small for TCP msg.
         The excess TCP msg data is still retained. */
      err = (int)size;
      break;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_socket_stream_read(%ld): %ld", stream->sock, err));

  return (err);
}

/*-------------------------------------------------------------------------
  Writes at most `size' bytes from the buffer `buffer' using the Winsock
  stream.
  -------------------------------------------------------------------------*/
static int
ssh_socket_stream_write(void *context,
                        const unsigned char *buf,
                        size_t size)
{
  SshSocketStream stream = (SshSocketStream)context;
  INT err = 0;

  SSH_ASSERT(stream != NULL);
  SSH_ASSERT(stream->sock != INVALID_SOCKET);
  SSH_ASSERT(!stream->destroyed);
  SSH_ASSERT(size <= 0xFFFFFFFF);

  if (!stream->disconnected)
    {
      /* Try to send data from buffer */
      err = send(stream->sock, buf, (int)size, 0);
      if (err != SOCKET_ERROR)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("ssh_socket_stream_write(%ld): %ld",
                     stream->sock, err));
          return (err);
        }

      err = WSAGetLastError();
      switch (err)
        {
        default:
          ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW, err);
          stream->write_has_failed = 1;
          ssh_socket_stream_set_request(stream);
          err = 0;
          break;

        case WSAEWOULDBLOCK:
        case WSAENOBUFS:
        case WSAEMSGSIZE:
        case WSAEHOSTUNREACH:
          stream->write_has_failed = 1;
          ssh_socket_stream_set_request(stream);
          err = -1;
          break;
        }
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_socket_stream_write(%ld): %ld", stream->sock, err));

  return (err);
}

/*---------------------------------------------------------------------------
  Signals that the application will not write anything more to the stream
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_output_eof(void *context)
{
  SshSocketStream stream = (SshSocketStream) context;

  SSH_ASSERT(stream != NULL);
  SSH_ASSERT(stream->sock != INVALID_SOCKET);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_socket_stream_output_eof(%ld)", stream->sock));

  shutdown(stream->sock, SD_SEND);
}


/*---------------------------------------------------------------------------
  Timed callback to notify application to perform read/write operations
  via stream callback.
  ---------------------------------------------------------------------------*/
static void
ssh_socket_stream_start_io_timeout(void *context)
{
  SshSocketStream stream = (SshSocketStream)context;

  if (stream->cb && !stream->destroyed)
    {
      stream->read_has_failed = 1;
      stream->write_has_failed = 1;
      ssh_socket_stream_set_request(stream);

      (*stream->cb)(SSH_STREAM_INPUT_AVAILABLE, stream->context);

      /* check that stream was not destroyed above! */
      if (!stream->destroyed)
        (*stream->cb)(SSH_STREAM_CAN_OUTPUT, stream->context);
    }
}


/*---------------------------------------------------------------------------
  Sets the callback that the stream uses to notify the application of
  events of interest.
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_set_stream_callback(void *context,
                                      SshStreamCallback stream_cb,
                                      void *stream_ctx)
{
  SshSocketStream stream = (SshSocketStream)context;

  SSH_ASSERT(stream != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_socket_stream_set_stream_callback(%ld)", stream->sock));

  stream->cb = stream_cb;
  stream->context = stream_ctx;

  /* Notify application by using the callback that it can
     execute read/write operations. */
  ssh_cancel_timeouts(ssh_socket_stream_start_io_timeout,
                                          (void *)context);
  if (stream_cb)
    ssh_xregister_timeout(0L, 0L,
                          ssh_socket_stream_start_io_timeout,
                                                  (void *)context);
}


/*---------------------------------------------------------------------------
  Delayed destruction of the given stream.
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_real_destroy(void *context)
{
  SshSocketStream stream = (SshSocketStream)context;

  memset(stream, 'F', sizeof(*stream));
  ssh_free(stream);
}


/*---------------------------------------------------------------------------
  Closes, destroys, and frees the given stream. Destruction is delayed and
  the actual freeing is done from the bottom of the event loop. This is
  needed because we might generated pending events for the object.
  --------------------------------------------------------------------------*/
static void
ssh_socket_stream_destroy(void *context)
{
  SshSocketStream stream = (SshSocketStream)context;

  SSH_ASSERT(stream != NULL);
  SSH_ASSERT(!stream->destroyed);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_socket_stream_destroy: socket[%ld]", stream->sock));

  ssh_cancel_timeouts(ssh_socket_stream_start_io_timeout, (void *)context);

  stream->destroyed = 1;
  stream->cb = NULL_FNPTR;

  /* Unregister the file descriptors from the event loop */
  if (stream->sock != INVALID_SOCKET)
    ssh_io_unregister_fd(stream->sock, FALSE);

  /* Close the file descriptors if appropriate. */
  if (stream->close_on_destroy)
    closesocket(stream->sock);

  /* Perform a delayed free of the stream context. */
  ssh_xregister_timeout(0, 0, ssh_socket_stream_real_destroy, stream);
}


/*---------------------------------------------------------------------------
  Returns the Windows socket associated into a given SSH stream.
  --------------------------------------------------------------------------*/
static SOCKET
ssh_socket_stream_get_socket(SshStream stream)
{
  if (!stream)
    return (INVALID_SOCKET);

  if (ssh_stream_get_methods(stream) != &ssh_socket_method_table)
    return (INVALID_SOCKET);

  return (((SshSocketStream)ssh_stream_get_context(stream))->sock);
}


/*---------------------------------------------------------------------------
  TCP connect platform methods
  --------------------------------------------------------------------------*/

static const SshTcpConnectMethodsStruct ssh_tcp_connect_methods =
{
  ssh_socket_low_connect,
  ssh_tcp_low_connect_ip,
  ssh_tcp_low_has_ip_options,
  ssh_tcp_low_get_ip_addresses,
  ssh_tcp_low_set_nodelay,
  ssh_tcp_low_set_keepalive,
  ssh_tcp_low_set_linger
};

SshTcpConnectMethods
ssh_tcp_connect_platform_methods(void **constructor_context_return)
{
  if (constructor_context_return)
    *constructor_context_return = NULL;
  return (SshTcpConnectMethods) &ssh_tcp_connect_methods;
}


/*---------------------------------------------------------------------------
  TCP listener platform methods
  --------------------------------------------------------------------------*/

static const SshTcpListenerMethodsStruct ssh_tcp_listener_methods =
{
  ssh_tcp_low_make_listener,
  ssh_tcp_low_make_listener_ip,
  ssh_tcp_low_listener_get_local_port_number,
  ssh_tcp_low_destroy_listener
};

SshTcpListenerMethods
ssh_tcp_listener_platform_methods(void **constructor_context_return)
{
  if (constructor_context_return)
    *constructor_context_return = NULL;
  return (SshTcpListenerMethods) &ssh_tcp_listener_methods;
}
