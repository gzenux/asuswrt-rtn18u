/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows implementation of the UDP communications interface.
*/

/*---------------------------------------------------------------------------
  INCLUDES
  ---------------------------------------------------------------------------*/

#define WIN32_LEAN_AND_MEAN
#include "sshincludes.h"
#include "sshudp.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "ssheloop.h"
#include "sshwinutil2.h"
#include "mswsock.h"

/*---------------------------------------------------------------------------
  DEFINES
  ---------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshNetUdp"

/*---------------------------------------------------------------------------
  TYPE DEFINITIONS
  ---------------------------------------------------------------------------*/

/* Internal representation of SSH UDP Listener structure */
struct SshUdpPlatformListenerRec
{
  /* Pointer to the generic listener object. */
  SshUdpListener listener;

  SOCKET sock;
  unsigned char connected:1;

  SshSockAddrStruct local;
  SshSockAddrStruct remote;

  SshIpAddrStruct last_dst;
  SshUInt16       last_port;
  SshUInt16       last_len;

  SshUdpCallback cb;
  void* ctx;

  int rd_cnt;
  int wr_cnt;

  struct SshUdpPlatformListenerRec *next;
};

typedef struct SshUdpPlatformListenerRec SshUdpPlatformListenerStruct;
typedef struct SshUdpPlatformListenerRec *SshUdpPlatformListener;

/*---------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  ---------------------------------------------------------------------------*/

static void
ssh_socket_udp_io_cb(unsigned int event,
                     void *context);

static SshUdpPlatformListener
ssh_udp_create_listener(SshIpAddr local_ip,
                        SshUInt16 local_port,
                        SshIpAddr remote_ip,
                        SshUInt16 remote_port,
                        int interface_index,
                        int routing_instance_id,
                        SshUdpListenerParams params,
                        SshUdpCallback cb,
                        void *ctx);

/*---------------------------------------------------------------------------
  Creates a listener for sending and receiving UDP packets.
  ---------------------------------------------------------------------------*/
static void *
udp_win32_make_listener(void *make_listener_method_context,
                        SshUdpListener generic_listener,
                        SshIpAddr local_addr, SshUInt16 local_port,
                        SshIpAddr remote_addr, SshUInt16 remote_port,
                        int interface_index,
                        int routing_instance_id,
                        SshUdpListenerParams params,
                        SshUdpCallback cb,
                        void *ctx)
{
  SshUdpPlatformListener listener = NULL;
  SshIpAddrStruct ipv4_any;
#if defined (WITH_IPV6)
  SshIpAddrStruct ipv6_any;
#endif /* IPv6*/

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_udp_make_listener()"));

  if (local_addr && SSH_IP_DEFINED(local_addr))
    {
      if (SSH_IP_IS4(local_addr))
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv4 only UDP listener for address %@",
                     ssh_ipaddr_render, local_addr));
          listener = ssh_udp_create_listener(local_addr, local_port,
                                             remote_addr, remote_port,
                                             interface_index,
                                             routing_instance_id,
                                             params, cb, ctx);

        }
      else
        {
#if defined (WITH_IPV6)
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv6 only UDP listener for address %@",
                     ssh_ipaddr_render, local_addr));
          listener = ssh_udp_create_listener(local_addr, local_port,
                                             remote_addr, remote_port,
                                             interface_index,
                                             routing_instance_id,
                                             params, cb, ctx);
#else
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("IPv6 is not supported on this platform"));
          return NULL;
#endif /* not WITH_IPV6 */
        }

    /* Bind generic listener objects to the platform dependent
     listeners. */
      if (listener)
        {
          listener->listener = generic_listener;
          if (listener->next)
            listener->next->listener = generic_listener;
        }
      return (listener);
    }

/* Let's determine the type of listener to create by the remote address. */
  if (remote_addr && SSH_IP_DEFINED(remote_addr))
    {
      if (SSH_IP_IS4(remote_addr))
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv4 only UDP listener for address %@",
                     ssh_ipaddr_render, remote_addr));
          listener = ssh_udp_create_listener(local_addr, local_port,
                                             remote_addr, remote_port,
                                             interface_index,
                                             routing_instance_id,
                                             params, cb, ctx);

        }
      else
        {
#if defined (WITH_IPV6)
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv6 only UDP listener for address %@",
                     ssh_ipaddr_render, remote_addr));
          listener = ssh_udp_create_listener(local_addr, local_port,
                                             remote_addr, remote_port,
                                             interface_index,
                                             routing_instance_id,
                                             params, cb, ctx);
#else
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("IPv6 is not supported on this platform"));
          return NULL;
#endif /* not WITH_IPV6 */
        }

    /* Bind generic listener objects to the platform dependent
     listeners. */
      if (listener)
        {
          listener->listener = generic_listener;
          if (listener->next)
            listener->next->listener = generic_listener;
        }
      return (listener);
    }

 /* Create a dual listener for both IPv4 and IPv6. */

    ssh_ipaddr_parse(&ipv4_any, SSH_IPADDR_ANY_IPV4);
#if defined (WITH_IPV6)
    ssh_ipaddr_parse(&ipv6_any, SSH_IPADDR_ANY_IPV6);
#endif /* WITH_IPV6 */

    /* Try to create IPv4 listener 1st */
    listener = ssh_udp_create_listener(&ipv4_any, local_port,
                                       remote_addr, remote_port,
                                       interface_index,
                                       routing_instance_id,
                                       params, cb, ctx);
#if defined (WITH_IPV6)
    if (listener)
    /* Create additional IPv6 listener */
    listener->next = ssh_udp_create_listener(&ipv6_any, local_port,
                                             remote_addr, remote_port,
                                             interface_index,
                                             routing_instance_id,
                                             params, cb, ctx);
    else
      /* Create only IPv6 listener */
      listener = ssh_udp_create_listener(&ipv6_any, local_port,
                                         remote_addr, remote_port,
                                         interface_index,
                                         routing_instance_id,
                                         params, cb, ctx);
#endif /* WITH_IPV6 */

    /* Bind generic listener objects to the platform dependent
       listeners. */
    if (listener)
      {
        listener->listener = generic_listener;
        if (listener->next)
          listener->next->listener = generic_listener;
      }
    return (listener);
}

/*---------------------------------------------------------------------------
  Destroys the udp listener
  ---------------------------------------------------------------------------*/
static void
udp_win32_destroy_listener(void *listener_context)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_udp_platform_destroy_listener()"));

  if (!listener)
    return;

  udp_win32_destroy_listener(listener->next);

  ssh_io_unregister_fd(listener->sock, FALSE);
  closesocket(listener->sock);

  ssh_free(listener);
}

/*---------------------------------------------------------------------------
  Reads the received UDP datagram from the listener.
  ---------------------------------------------------------------------------*/
static SshUdpError
udp_win32_read(void *listener_context,
               SshIpAddr remote_addr,
               SshUInt16 *remote_port,
               unsigned char *buf,
               size_t buf_len,
               size_t *bytes_read)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
  int err = 0;
  unsigned long cnt = 0;
  SshUdpError udp_err = SSH_UDP_OK;
  int addr_len = sizeof(SshSockAddrStruct);
  SshSockAddrStruct addr;

  if (!listener)
    return (SSH_UDP_HOST_UNREACHABLE);

  /* Tries to read data and then process results */
  listener->rd_cnt++;
  err = recvfrom(listener->sock, buf, (int)buf_len, 0,
                 (SOCKADDR *)&addr, &addr_len);

  if (err == 0)
    {
      /* UDP socket has been closed */
      udp_err = SSH_UDP_HOST_UNREACHABLE;
    }
  else if (err == SOCKET_ERROR)
    {
      /* UDP socket read failed */
      err = WSAGetLastError();

      if (err != WSAEWOULDBLOCK)
        ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, err);

      switch (err)
        {
        default:
          udp_err = SSH_UDP_HOST_UNREACHABLE;
          break;

        case WSAEWOULDBLOCK:
          udp_err = SSH_UDP_NO_DATA;
          break;

        case WSAECONNRESET:
          udp_err = SSH_UDP_PORT_UNREACHABLE;
          break;
        }
    }
  else
    {
      /* Read succeeded */
      cnt = err;
    }

  if (addr_len > 0 && cnt > 0)
    {
      /* Format destination port number into user buffer. */
      if (remote_port != NULL)
        *remote_port = ntohs(SS_PORT((SOCKADDR *)&addr));

      /* Format destination address into user buffer. */
      if (remote_addr != NULL)
        {
          if (((SOCKADDR *)&addr)->sa_family == AF_INET)
            SSH_IP4_DECODE(remote_addr, &(((SOCKADDR_IN *)&addr)->sin_addr));
          else if (((SOCKADDR *)&addr)->sa_family == AF_INET6)
            SSH_IP6_DECODE(remote_addr, &(((SOCKADDR_IN6 *)&addr)->sin6_addr));
          else
            SSH_NOTREACHED;
        }
    }

  if (cnt > 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_udp_platform_read(%d): Read %ld bytes from %@:%d",
                 listener->sock, cnt,
                 ssh_ipaddr_render, remote_addr,
                 remote_port ? *remote_port : 0));
    }

  if (bytes_read)
    *bytes_read = cnt;

  if ((udp_err == SSH_UDP_OK) || (udp_err == SSH_UDP_NO_DATA))
    {
      /* Reset the read count */
      listener->rd_cnt = 0;
    }

  return (udp_err);
}

/*---------------------------------------------------------------------------
  Sends UDP datagram to remote destination
  ---------------------------------------------------------------------------*/
static SshUdpError
udp_win32_send(void *listener_context,
               SshIpAddr remote_address,
               SshUInt16 remote_port,
               const unsigned char *buf,
               size_t buf_len)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
  int err = 0;
  int addr_len = 0;

  if (buf == NULL || buf_len == 0)
    return SSH_UDP_INVALID_ARGUMENTS;

  if (listener->connected)
    {
      if (remote_port != 0)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("ssh_udp_platform_send: Remote port[%d] specified for "
                   "connected socket, ignored", remote_port));

      if (remote_address != NULL)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("ssh_udp_platform_send: Remote address[%@] specified for "
                   "connected socket, ignored",
                   ssh_ipaddr_render, remote_address));

      /* Send the packet to the connected socket. */
      err = send(listener->sock, buf, (int)buf_len, 0);
    }
  else
    {
      int pf = PF_UNSPEC;

      if (listener->last_port != remote_port ||
          SSH_IP_CMP(&listener->last_dst, remote_address))
        {/* Send the packet to remote address */
          if (ssh_socket_address_create(remote_address,
                                        remote_port,
                                        &addr_len,
                                        &pf,
                                        &listener->remote) == NULL)
            goto fail;

          listener->last_dst = *remote_address;
          listener->last_port = remote_port;
          listener->last_len  = addr_len;
        }

      /* Send the packet */
      listener->wr_cnt++;

      err = sendto(listener->sock,
                   buf, (int)buf_len, 0,
                   (SOCKADDR *)&listener->remote, listener->last_len);
    }

  if (err != SOCKET_ERROR)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_udp_platform_send(): Send %ld bytes to %@:%d",
                 (LONG)buf_len,
                 ssh_ipaddr_render, remote_address, remote_port));
    }
  else
    {
 fail:
      listener->wr_cnt = 0;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_udp_platform_send(): Send %ld bytes to %@:%d failed %d",
                 (LONG)buf_len,
                 ssh_ipaddr_render, remote_address, remote_port));
    }

  return SSH_UDP_OK;
}

/* Add membership to given multicast group */

static SshUdpError
udp_win32_multicast_add_membership(void *listener,
                                   SshIpAddr group, SshIpAddr iface)
{
  ssh_warning("ssh_udp_platform_multicast_add_membership not implemented yet");

  return SSH_UDP_INVALID_ARGUMENTS;
}

/* Drop membership to given multicast group */

static SshUdpError
udp_win32_multicast_drop_membership(void *listener,
                                    SshIpAddr group, SshIpAddr iface)
{
  ssh_warning("ssh_udp_platform_multicast_drop_membership "
              "not implemented yet");

  return SSH_UDP_INVALID_ARGUMENTS;
}

static Boolean
udp_low_get_ip_addresses(void *listener_context,
                         SshIpAddr local_ip,
                         SshUInt16 *local_port,
                         SshIpAddr remote_ip,
                         SshUInt16 *remote_port)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
  SshSockAddrStruct ss;
  SOCKADDR *sa = (SOCKADDR *) &ss;
  INT sa_len = sizeof(SshSockAddrStruct);

  if (listener == NULL)
    return FALSE;

  if (listener->sock == INVALID_SOCKET)
    return (FALSE);

  if (local_ip || local_port)
    {
      memset(sa, 0, sa_len);
      if (getsockname(listener->sock, sa, &sa_len) == SOCKET_ERROR)
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
      if (getpeername(listener->sock, sa, &sa_len) == SOCKET_ERROR)
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

/* Platform dependent UDP methods. */
static const SshUdpMethodsStruct ssh_udp_methods =
{
  udp_win32_make_listener,
  udp_win32_destroy_listener,
  udp_win32_read,
  udp_win32_send,
  udp_win32_multicast_add_membership,
  udp_win32_multicast_drop_membership,
  udp_low_get_ip_addresses
};

/* Fetch the platform dependent UDP methods and constructor
   context. */

SshUdpMethods
ssh_udp_platform_methods(void **constructor_context_return)
{
  *constructor_context_return = NULL;
  return (SshUdpMethods) &ssh_udp_methods;
}


/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  ---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
  Event loop callback function for UDP socket state notification.
  ---------------------------------------------------------------------------*/
static void
ssh_socket_udp_io_cb(unsigned int event,
                     void *context)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) context;

  if (!listener)
    return;

  if (event == SSH_IO_CLOSED)
    {
      /* Socket has been closed */
      if (listener->cb)
        listener->cb(listener->listener, listener->ctx);
    }
  else
    {
      if ((event & SSH_IO_READ) == SSH_IO_READ)
        {
          /* Incoming data available */
          if (listener->cb && !listener->rd_cnt)
            listener->cb(listener->listener, listener->ctx);
        }
      if ((event & SSH_IO_WRITE) == SSH_IO_WRITE)
        {
          /* Socket available for sending data */
          if (listener->cb && !listener->wr_cnt)
            listener->cb(listener->listener, listener->ctx);
        }
    }
}

/*---------------------------------------------------------------------------
  Creates a new IP address/port listener for UDP data communication.
  ---------------------------------------------------------------------------*/
static SshUdpPlatformListener
ssh_udp_create_listener(SshIpAddr local_addr,
                        SshUInt16 local_port,
                        SshIpAddr remote_addr,
                        SshUInt16 remote_port,
                        int interface_index,
                        int routing_instance_id,
                        SshUdpListenerParams params,
                        SshUdpCallback cb,
                        void *ctx)
{
  SshUdpPlatformListener obj = ssh_calloc(1, sizeof(*obj));
  int sa_len = 0, err = 0, pf = PF_UNSPEC;
  SshIpAddrStruct laddr_struct, *laddr;
  SshUInt16 lport;

  if (!obj)
    return (NULL);

  obj->ctx = ctx;
  obj->cb = cb;
  obj->next = NULL;
  obj->sock = INVALID_SOCKET;
  obj->connected = 0;
  obj->rd_cnt = 0;
  obj->wr_cnt = 0;

  do
    {
      DWORD bytes_returned = 0;
      BOOL behavior = FALSE;

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

      if (laddr)
        {
          if (ssh_socket_address_create(laddr, lport, &sa_len,
                                        &pf, &obj->local) == NULL)
            {
              ssh_free(obj);
              return (NULL);
            }

          /* Try to create a socket */
          obj->sock = socket(((SOCKADDR *)(&obj->local))->sa_family,
                             SOCK_DGRAM, pf);
          if (obj->sock == INVALID_SOCKET)
            {
              err = SOCKET_ERROR;
              break;
            }
          ssh_socket_set_reuseport(obj->sock);
          ssh_socket_set_reuseaddr(obj->sock);

          /* Ignore ICMP Port Unreachable messages */
          err = WSAIoctl(obj->sock, SIO_UDP_CONNRESET,
                         &behavior, sizeof(behavior),
                         NULL, 0, &bytes_returned,
                         NULL, NULL);

          if (SOCKET_ERROR == err)
            break;

          /* Try to bind the socket into specified address/port */
          err = bind(obj->sock, (SOCKADDR *)&obj->local, sa_len);
          if (err == SOCKET_ERROR)
            break;
        }
      /* Check if we have a valid remote address for connection */
      if (remote_addr && SSH_IP_DEFINED(remote_addr))
        {
          if (ssh_socket_address_create(remote_addr, remote_port, &sa_len,
                                        &pf, &obj->remote) == NULL)
            {
              ssh_free(obj);
              return (NULL);
            }

          if (obj->sock == INVALID_SOCKET)
            {
              obj->sock = socket(((SOCKADDR *)(&obj->remote))->sa_family,
                                 SOCK_DGRAM, pf);
              if (obj->sock == INVALID_SOCKET)
                {
                  err = SOCKET_ERROR;
                  break;
                }

              /* Ignore ICMP Port Unreachable messages */
              err = WSAIoctl(obj->sock, SIO_UDP_CONNRESET,
                             &behavior, sizeof(behavior),
                             NULL, 0, &bytes_returned,
                             NULL, NULL);

              if (SOCKET_ERROR == err)
                break;
            }
          /*Set socket to connected state and then try to make a connection*/
          obj->connected = 1;
          err = connect(obj->sock, (SOCKADDR *)&obj->remote, sa_len);

          if (err == -1)
            {
#ifdef DEBUG_LIGHT
              ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, errno);
#endif /* DEBUG_LIGHT */
              closesocket(obj->sock);
              ssh_free(obj);
              return NULL;
            }
        }
    }
  while (0);

  /* Error handling */
  if (err)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Create UDP listener failed: Local[%@:%d], Remote[%@:%d]",
                 ssh_ipaddr_render, local_addr, local_port,
                 ssh_ipaddr_render, remote_addr, remote_port));

      ssh_win_show_error(SSH_DEBUG_MODULE, SSH_D_FAIL, WSAGetLastError());

      if (obj->sock != INVALID_SOCKET)
        closesocket(obj->sock);

      ssh_free(obj);

      return (NULL);
    }

  /* set some common options for sockets */
  ssh_socket_set_common_options(obj->sock, params);

  ssh_io_register_fd(obj->sock, ssh_socket_udp_io_cb, (void*) obj);
  ssh_io_set_fd_request(obj->sock, FD_READ | FD_CLOSE);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Create UDP listener succeeded: Local[%@:%d], Remote[%@:%d]",
             ssh_ipaddr_render, local_addr, local_port,
             ssh_ipaddr_render, remote_addr, remote_port));

  return (obj);
}
