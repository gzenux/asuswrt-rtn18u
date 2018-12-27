/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Function declarations for miscellaneous Windows utilities.
*/

#ifndef SSHWINUTIL_H
#define SSHWINUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sshudp.h"

/* Send buffer size for sockets */
#define SSH_SOCKET_SNDBUF_SIZE 65535
/* Receive buffer size for sockets */
#define SSH_SOCKET_RCVBUF_SIZE 65535

struct SshSockAddrRec
{
  union
  {
    SOCKADDR_IN  s4;

#ifdef WITH_IPV6
    SOCKADDR_IN6 s6;
#endif /* WITH_IPV6 */
  } u;
};

typedef struct SshSockAddrRec SshSockAddrStruct;
typedef struct SshSockAddrRec *SshSockAddr;

/*-------------------------------------------------------------------------
  Displays a Windows system error using SSH debug utilities.
  -------------------------------------------------------------------------*/
void
ssh_win_show_error(const char *module,
                   int level,
                   int err);

/*-------------------------------------------------------------------------
  Returns the port number as string from Socket Address.
  -------------------------------------------------------------------------*/
Boolean
ssh_socket_address_get_port_value(struct sockaddr *sa,
                                  SshUInt16 *port);

Boolean
ssh_socket_address_get_port(struct sockaddr *sa,
                            char *buf,
                            size_t buf_len);

/*-------------------------------------------------------------------------
  Returns the IP Address as string from socket address.
  -------------------------------------------------------------------------*/
Boolean
ssh_socket_address_get_ip(struct sockaddr *sa,
                          SshIpAddr ip_addr);

Boolean
ssh_socket_address_get_ipaddr(struct sockaddr *sa,
                              char *buf,
                              size_t buf_len);

/*-------------------------------------------------------------------------
  Creates a new socket address from given ip address & port.
  -------------------------------------------------------------------------*/
SshSockAddr
ssh_socket_address_create(SshIpAddr ip_addr,
                          SshUInt16 port,
                          int *addr_len,
                          int *protocol_family,
                          SshSockAddr sa);

/*---------------------------------------------------------------------------
  Allows the socket to be bound to an address that is already in use.
  --------------------------------------------------------------------------*/
void
ssh_socket_set_reuseaddr(SOCKET sock);

/*---------------------------------------------------------------------------
  Allows the socket to be bound to a port that is allready in use.
  --------------------------------------------------------------------------*/
void
ssh_socket_set_reuseport(SOCKET sock);

/*---------------------------------------------------------------------------
  Set some common options for both IPv4 and IPv6 sockets (SO_SNDBUF,
  SO_RCVBUF, SO_BROADCAST)
  --------------------------------------------------------------------------*/
void ssh_socket_set_common_options(SOCKET sock, SshUdpListenerParams params);

/*-------------------------------------------------------------------------
  Resolves the scope ID of the given IPv6 link-local address.
  -------------------------------------------------------------------------*/
#ifdef WITH_IPV6
Boolean
ssh_win32_ipaddr_resolve_scope_id(SshScopeId scope,
                                  const unsigned char *id);
#endif (/* WITH_IPV6 */

#ifdef __cplusplus
}
#endif

/*---------------------------------------------------------------------------
  Selects a suitable local IP address for connecting to a remote address
  based on the routing table if necessary.
  --------------------------------------------------------------------------*/
Boolean
ssh_win32_select_local_address(SshIpAddr local_addr, SshIpAddr remote_addr);

#endif /* SSHWINUTIL_H */
