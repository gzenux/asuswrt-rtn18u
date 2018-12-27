/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for miscellaneous 32/64-bit Windows utilities.
*/

/*---------------------------------------------------------------------------
  INCLUDES
  ---------------------------------------------------------------------------*/

#define WIN32_LEAN_AND_MEAN

#include "sshincludes.h"
#include "sshinet.h"
#include "sshwinutil2.h"

#include <iphlpapi.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi")

/*---------------------------------------------------------------------------
  DEFINES
  ---------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshNetUtil"

/*---------------------------------------------------------------------------
  CONSTANTS
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  EXTERNALS
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  LOCAL VARIABLES
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Tries to resolve the scope ID for the specified IPv6 link-local socket
  address.
  ---------------------------------------------------------------------------*/
static Boolean
ssh_ipv6_scope_id_resolve(SOCKADDR_IN6 *addr,
                          int addr_len)
{
  SOCKADDR_IN6 route_addr;
  SOCKET sock;
  DWORD bytes_returned = 0;
  Boolean status = FALSE;
  int rc;

  /* Create a raw IPv6 socket to be used for "routing" */
  sock = socket(AF_INET6, SOCK_RAW, PF_INET6);
  if (sock == INVALID_SOCKET)
    return FALSE;

  /* Try to find correct "routing interface" for the specified address */
  rc = WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, addr, addr_len,
                &route_addr, sizeof(route_addr), &bytes_returned, NULL, NULL);

  if ((rc != SOCKET_ERROR) && (bytes_returned == sizeof(route_addr)))
    {
      addr->sin6_scope_id = route_addr.sin6_scope_id;
      status = TRUE;
    }

  closesocket(sock);

  return status;
}


/*---------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Displays system error message using SSH debug utilities
  ---------------------------------------------------------------------------*/
void
ssh_win_show_error(const char *module,
                   int level,
                   int err)
{
  LPVOID msg = NULL;
  DWORD ret = 0;

  ret = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                      | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL,
                      err,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR) &msg,
                      0,
                      NULL);

  if (!ret)
    {
      /* Windows CE based platforms are usually built without system level
         message tables (to reduce memory footprint), so we can't display
         the user friendly error message. */
      SSH_DEBUG(level, ("%s: error=%u (0x%08X)", module, err, err));

      if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        GetLastError(),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPTSTR) &msg,
                        0,
                        NULL))
        {
          SSH_DEBUG(level, ("FormatMessage error(): %s", msg));
          LocalFree(msg);
        }
    }
  else
    {
      SSH_DEBUG(level, ("%s: %s", module, msg));
      LocalFree(msg);
    }
}


/*---------------------------------------------------------------------------
  Allows the socket to be bound to an address that is already in use.
  --------------------------------------------------------------------------*/
void
ssh_socket_set_reuseaddr(SOCKET sock)
{
#ifdef SO_REUSEADDR
  int on = 1;

  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (VOID *)&on, sizeof(on));
#endif /* SO_REUSEADDR */
}

/*---------------------------------------------------------------------------
  Allows the socket to be bound to a port that is allready in use.
  --------------------------------------------------------------------------*/
void
ssh_socket_set_reuseport(SOCKET sock)
{
#ifdef SO_REUSEPORT
  int on = 1;

  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (VOID *)&on, sizeof(on));
#endif /* SO_REUSEPORT */
 }

/* Set some common options for both IPv4 and IPv6 sockets (SO_SNDBUF,
   SO_RCVBUF, SO_BROADCAST) */
void ssh_socket_set_common_options(SOCKET sock, SshUdpListenerParams params)
{
#ifdef SO_BROADCAST
  if (params && params->broadcasting)
    {
      char opt = '1';
      int err = 0;
      int opt_len = sizeof(opt);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting broadcasting"));

      err = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt,
                       opt_len);
      if (err == SOCKET_ERROR)
        ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW,
                           WSAGetLastError());
    }
#endif /* SO_BROADCAST */

    {
      int buf, err = 0;
      /* Not considering for WINCE platform. Even though WINCE supports
         SO_SNDBUF, SO_RCVBUF with default value of 8192 bytes */
#ifdef SO_SNDBUF
      buf = SSH_SOCKET_SNDBUF_SIZE;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting send buffer size for socket"));

      err = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*) &buf,
                       sizeof(int));
      if (err == SOCKET_ERROR)
        ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW,
                           WSAGetLastError());
#endif /* SO_SNDBUF */

#ifdef SO_RCVBUF
      buf = SSH_SOCKET_RCVBUF_SIZE;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting receive buffer size for socket"));

      err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*) &buf,
                       sizeof(int));
      if (err == SOCKET_ERROR)
        ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_NICETOKNOW,
                           WSAGetLastError());
#endif /* SO_RCVBUF */
    }
}

/*---------------------------------------------------------------------------
  Converts IP address string/port number to socket address format
  ---------------------------------------------------------------------------*/
SshSockAddr
ssh_socket_address_create(SshIpAddr ip,
                          SshUInt16 port,
                          int *addr_len,
                          int *protocol_family,
                          SshSockAddr sa)
{
  char addr_str[SSH_IP_ADDR_STRING_SIZE];
#ifdef UNICODE
  WCHAR uc_addr_str[64];
#endif /* UNICODE */
  int sa_len = sizeof(SshSockAddrStruct);
  int rc = 0;

  SSH_ASSERT(SSH_IP_DEFINED(ip));
  SSH_ASSERT(sa != NULL);

  if (addr_len)
    *addr_len = 0;

  if (protocol_family)
    *protocol_family = PF_UNSPEC;

  /* Print address into buffer */
  ssh_ipaddr_print(ip, addr_str, sizeof(addr_str));

  /* Set the socket address/port info depending on the address family */
  if (SSH_IP_IS4(ip))
    {
#ifdef UNICODE
      ssh_ascii_to_unicode(uc_addr_str, sizeof(uc_addr_str), addr_str);
      rc = WSAStringToAddress(uc_addr_str, AF_INET, NULL,
                              (SOCKADDR *)sa, &sa_len);
#else
      rc = WSAStringToAddress(addr_str, AF_INET, NULL,
                              (SOCKADDR *)sa, &sa_len);
#endif /* UNICODE */
      if (rc)
        ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_ERROR, WSAGetLastError());

      SS_PORT((SOCKADDR *)sa) = htons((unsigned short)port);
    }
  else if (SSH_IP_IS6(ip))
    {
#ifdef UNICODE
      ssh_ascii_to_unicode(uc_addr_str, sizeof(uc_addr_str), addr_str);
      rc = WSAStringToAddress(uc_addr_str, AF_INET6, NULL,
                              (SOCKADDR *)sa, &sa_len);
#else
      rc = WSAStringToAddress(addr_str, AF_INET6, NULL,
                              (SOCKADDR *)sa, &sa_len);
#endif /* UNICODE */
      if (rc)
        {
          /* We don't use SSH_D_ERROR debug level here, because it's
             normal that WSAStringToAddress() fails on machines not
             having IPv6 stack installed. */
          ssh_win_show_error(SSH_DEBUG_MODULE,
                             SSH_D_FAIL, WSAGetLastError());
        }

      SS_PORT((SOCKADDR *)sa) = htons((unsigned short)port);
    }

  /* Error handling */
  if (rc)
    {
      return (NULL);
    }
  else
    {
      /* Address conversion succeeded so update the address length */
      if (addr_len)
        *addr_len = sa_len;
    }

  return (sa);
}


/*---------------------------------------------------------------------------
  Returns socket's port number(host-byte order) as SshUInt16 / as string
  ---------------------------------------------------------------------------*/
Boolean
ssh_socket_address_get_port_value(struct sockaddr *sa,
                                  SshUInt16 *port)
{
  USHORT p = 0;

  if (!sa || !port)
    return (FALSE);

  p = SS_PORT(sa);
  *port = (SshUInt16) ntohs(p);

  return (TRUE);
}

Boolean
ssh_socket_address_get_port(struct sockaddr *sa,
                            char *buf,
                            size_t buflen)
{
  SshUInt16 port = 0;

  if (!sa || !buf || buflen == 0)
    return (FALSE);

  if (ssh_socket_address_get_port_value(sa, &port) == FALSE)
    return (FALSE);

  ssh_snprintf(buf, buflen, "%u", port);

  return (TRUE);
}

/*---------------------------------------------------------------------------
  Returns socket's IP address as SshIpAddr / as string
  ---------------------------------------------------------------------------*/
Boolean
ssh_socket_address_get_ip(struct sockaddr *sa,
                          SshIpAddr ip_addr)
{
  /* Sanity checks for input args */
  if (!sa || !ip_addr)
    return (FALSE);

  /* Convert sockaddr to SSH specific address format */
  if (sa->sa_family == AF_INET)
    SSH_IP_DECODE(ip_addr, &(((SOCKADDR_IN *) sa)->sin_addr), 4);
  else if (sa->sa_family == AF_INET6)
    SSH_IP_DECODE(ip_addr, &(((SOCKADDR_IN6 *) sa)->sin6_addr), 16);
  else
    return (FALSE);

  return (TRUE);
}

Boolean
ssh_socket_address_get_ipaddr(struct sockaddr *sa,
                              char *buf,
                              size_t buf_len)
{
  SshIpAddrStruct ip_addr;

  /* Sanity checks for input args */
  if (!sa || !buf || buf_len == 0)
    return (FALSE);

  /* Init to defaults */
  memset(buf, 0, buf_len);
  memset(&ip_addr, 0, sizeof(ip_addr));

  if (ssh_socket_address_get_ip(sa, &ip_addr) == FALSE)
    return (FALSE);

  /* Print address into buffer */
  ssh_ipaddr_print(&ip_addr, buf, buf_len);

  return (TRUE);
}


#ifdef WITH_IPV6
Boolean
ssh_win32_ipaddr_resolve_scope_id(SshScopeId scope,
                                  const unsigned char *addr_str)
{
  SshIpAddrStruct ip_addr;
  SshSockAddrStruct sock_addr;
  int addr_len = 0;
  int proto;

  if (!ssh_ipaddr_parse(&ip_addr, addr_str))
    return FALSE;

  if (SSH_IP_IS4(&ip_addr))
    return FALSE;

  if (SSH_IP_IS6(&ip_addr) && SSH_IP6_IS_LINK_LOCAL(&ip_addr))
    {
#ifdef UNICODE
      size_t uc_copy_size = (ssh_ustrlen(addr_str) + 1 ) * sizeof(WCHAR);
      WCHAR *copy = ssh_calloc(1, uc_copy_size);

      if (copy != NULL)
        ssh_ascii_to_unicode(copy, uc_copy_size, addr_str);
#else
      char *copy = ssh_strdup(addr_str);
#endif /* UNICODE */

      addr_len = sizeof(SshSockAddrStruct);

      if (copy != NULL)
        {
          int rc;
          TCHAR *dest = _tcschr(copy, '%');

          if (dest)
            *dest = 0;

          rc = WSAStringToAddress(copy, AF_INET6, NULL,
                                  (SOCKADDR *)&sock_addr, &addr_len);

          if ((rc == 0) && (addr_len == sizeof(SOCKADDR_IN6)))
            {
              if (!ssh_ipv6_scope_id_resolve((SOCKADDR_IN6 *)&sock_addr.u.s6,
                                             addr_len))
                {
                  ssh_free(copy);
                  return FALSE;
                }
            }

          ssh_free(copy);
        }
    }
  else
    {
      if (ssh_socket_address_create(&ip_addr, 0, &addr_len,
                                    &proto, &sock_addr) == NULL)
        goto fail;
    }

  if (addr_len >= sizeof(SOCKADDR_IN6))
    {
      scope->scope_id_union.ui32 =
        ((SOCKADDR_IN6 *)&(sock_addr.u.s6))->sin6_scope_id;
      return TRUE;
    }

 fail:
  return FALSE;
}
#endif /* WITH_IPV6 */


#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
/*---------------------------------------------------------------------------
  Selects a suitable local IP address for connecting to a remote address
  based on the routing table if necessary.
  ---------------------------------------------------------------------------*/
Boolean
ssh_win32_select_local_address(SshIpAddr local_addr, SshIpAddr remote_addr)
{
  IPAddr r_addr;
  DWORD if_index, size, status, i;
  MIB_IPADDRTABLE *addr_table = NULL;
  MIB_IPADDRROW *addr_row;
  Boolean ok = FALSE;

  if (SSH_IP_IS6(remote_addr))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Selecting IPv6 local address not supported"));
      goto end;
    }

  SSH_IP4_ENCODE(remote_addr, (SshUInt8 *)&r_addr);

  if (GetBestInterface(r_addr, &if_index) != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get best interface to %@",
                             ssh_ipaddr_render, remote_addr));
      goto end;
    }

  size = 0;
  while ((status = GetIpAddrTable(addr_table, &size, FALSE)) ==
         ERROR_INSUFFICIENT_BUFFER)
    {
      if (addr_table)
        ssh_free(addr_table);
      if (!(addr_table = ssh_malloc(size)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate IP address table"));
          goto end;
        }
    }
  if (status != NO_ERROR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get IP address table"));
      goto end;
    }

  for (i = 0; i < addr_table->dwNumEntries; i++)
    {
      addr_row = &addr_table->table[i];
      if (addr_row->dwIndex == if_index)
        break;
    }
  if (i >= addr_table->dwNumEntries)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot find IP address for if index 0x%x",
                             (unsigned)if_index));
      goto end;
    }

  SSH_IP4_DECODE(local_addr, (SshUInt8 *)&addr_row->dwAddr);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Using local address %@ to connect to %@",
                               ssh_ipaddr_render, local_addr,
                               ssh_ipaddr_render, remote_addr));
  ok = TRUE;

 end:
  if (addr_table)
    ssh_free(addr_table);
  return ok;
}
#else /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */
Boolean
ssh_win32_select_local_address(SshIpAddr local_addr, SshIpAddr remote_addr)
{
  return FALSE;
}
#endif /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */
