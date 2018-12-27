/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Unix implementation of the UDP communications interface.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshudp.h"
#include "ssheloop.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshUdp"

#include <sys/socket.h>
#ifdef HAVE_MVL_VRF
#include <sys/vrf.h>
#include "sshvrf.h"
#endif /* HAVE_MVL_VRF */
#ifdef HAVE_WRL_VRF
#define CONFIG_VIRTUAL_ROUTING
#include <linux/sockios.h>
#endif /*  HAVE_WRL_VRF */
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTM_H */
#if !defined(__PARAGON__)
#include <netinet/ip.h>
#endif /* !__PARAGON__ */

#if defined(HAVE_SOCKADDR_IN6_STRUCT) && defined(WITH_IPV6)
/* Currently, we include the IPv6 code only if we have the
   `sockaddr_in6' structure. */
#define SSH_HAVE_IPV6
#ifdef IPV6_JOIN_GROUP
#define SSH_HAVE_IPV6_MULTICAST
#endif /* IPV6_JOIN_GROUP */
#endif /* HAVE_SOCKADDR_IN6_STRUCT && WITH_IPV6 */

/* Internal representation of Listener structure, not exported */
struct SshUdpPlatformListenerRec
{
  /* Pointer to the generic listener object. */
  SshUdpListener listener;

  SshIOHandle sock;
  Boolean ipv6;
  struct SshUdpPlatformListenerRec *sibling;
  SshUdpCallback callback;
  void *context;
  Boolean connected;
#ifdef SSH_HAVE_IPV6
  Boolean scope_id_cached;
  SshScopeIdStruct cached_scope_id;
#endif /* SSH_HAVE_IPV6 */
};

typedef struct SshUdpPlatformListenerRec SshUdpPlatformListenerStruct;
typedef struct SshUdpPlatformListenerRec *SshUdpPlatformListener;

static void
ssh_udp_io_cb(unsigned int events, void *context)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener)context;

  if (events & SSH_IO_READ)
    {
      /* Call the callback to inform about a received packet or
         notification. */
      if (listener->callback)
        (*listener->callback)(listener->listener, listener->context);
    }
}

/* Set the common (both IPv4 and IPv6) socket options for the UDP
   listener `listener'. */

static Boolean
ssh_udp_set_common_socket_options(SshUdpPlatformListener listener,
                                  SshUdpListenerParams params,
                                  int routing_instance_id)
{
#ifdef SO_REUSEADDR
  {
    int value;

    value = 1;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_REUSEADDR, (void *) &value,
                   (ssh_socklen_t) sizeof(value)) == -1)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("ssh_udp_set_common_socket_options: setsockopt " \
                   "SO_REUSEADDR failed: %s", strerror(errno)));
      }
  }
#endif /* SO_REUSEADDR */
#ifdef SO_REUSEPORT
  {
    int value;

    value = 1;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_REUSEPORT, (void *) &value,
                   (ssh_socklen_t) sizeof(value)) == -1)
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("ssh_udp_set_common_socket_options: setsockopt " \
                   "SO_REUSEPORT failed: %s", strerror(errno)));
      }
  }
#endif /* SO_REUSEPORT */
#ifdef HAVE_MVL_VRF
  if (routing_instance_id >= 0)
    {
      const char *value = NULL;

      value = ssh_vrf_find_name_by_id(routing_instance_id);
      if (value == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Routing instance %d not found", routing_instance_id));
          return FALSE;
        }
      if (setsockopt(listener->sock, SOL_SOCKET, SO_SOCKVRF,
                     value, sizeof(value)) == -1)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("setsockopt SO_SOCKVRF failed: %s", strerror(errno)));
          return FALSE;
        }
    }
#elif defined(HAVE_WRL_VRF)
  if (routing_instance_id >= 0)
    {
      if (setsockopt(listener->sock, SOL_SOCKET, SO_VR_ID,
                    (void *) &routing_instance_id, sizeof(routing_instance_id))
              == -1)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("setsockopt SO_VR_ID failed: %s", strerror(errno)));
          return FALSE;
        }
    }
#else /* HAVE_MVL_VRF */
  if (routing_instance_id > 0)
    {
      ssh_fatal("VRF not supported!");
      return FALSE;
    }
#endif /* HAVE_MVL_VRF */

  return TRUE;
}

/* Set more common (both IPv4 and IPv6) socket options for the UDP
   listener `listener'.  These are set after the socket is bound to IP
   addresses. */

static void
ssh_udp_set_more_common_socket_options(SshUdpPlatformListener listener,
                                       SshUdpListenerParams params)
{
#ifdef SO_SNDBUF
  {
    int buf_len;

    buf_len = 65535;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_SNDBUF, (void *)&buf_len,
                   (ssh_socklen_t) sizeof(int)) == -1)
      {
        SSH_DEBUG(2, ("ssh_udp_set_more_common_socket_options: " \
                      "setsockopt SO_SNDBUF failed: %s", strerror(errno)));
      }
  }
#endif /* SO_SNDBUF */

#ifdef SO_RCVBUF
  {
    int buf_len;

    buf_len = 65535;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUF, (void *)&buf_len,
                   (ssh_socklen_t) sizeof(int)) == -1)
      {
        SSH_DEBUG(2, ("ssh_udp_set_more_common_socket_options: " \
                      "setsockopt SO_RCVBUF failed: %s", strerror(errno)));
      }
  }
#endif /* SO_RCVBUF */
#ifdef SO_BROADCAST
  if (params && params->broadcasting)
    {
      int option = 1;

      if (setsockopt(listener->sock, SOL_SOCKET, SO_BROADCAST, (void *)&option,
                     (ssh_socklen_t) sizeof(int)) == -1)
        SSH_DEBUG(SSH_D_FAIL,
                  ("setsockopt SO_BROADCAST failed: %s", strerror(errno)));
    }
#endif /* SO_BROADCAST */
  if (params && params->multicast_hops)



    ssh_fatal("SshUdpListenerParamsStruct.multicast_hops "
              "not implemented yet!");
  if (params && params->multicast_loopback)



    ssh_fatal("SshUdpListenerParamsStruct.multicast_loopback "
              "not implemented yet!");
}



/* Creates an IPv4 UDP listener. */

static SshUdpPlatformListener
ssh_udp_make_ip4_listener(SshUdpListener generic_listener,
                          SshIpAddr l_addr, SshUInt16 l_port,
                          SshIpAddr r_addr, SshUInt16 r_port,
                          int interface_index,
                          int routing_instance_id,
                          SshUdpListenerParams params,
                          SshUdpCallback callback,
                          void *context)
{
  SshUdpPlatformListener listener;
  struct sockaddr_in sinaddr;
  int ret;

  /* Allocate and initialize the listener context. */
  listener = ssh_calloc(1, sizeof(*listener));

  if (listener == NULL)
    goto error;

  listener->listener = generic_listener;
  listener->ipv6 = FALSE;
  listener->context = context;
  listener->callback = callback;
  listener->connected = FALSE;

  /* Create the socket. */
  listener->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (listener->sock == -1)
    goto error;

  /* Set the common socket options. */
  if (ssh_udp_set_common_socket_options(listener, params, routing_instance_id)
      == FALSE)
    goto error;





  if ((l_addr && SSH_IP_DEFINED(l_addr)) || l_port != 0)
    {
      /* Initialize the address structure for the local address. */
      memset(&sinaddr, 0, sizeof(sinaddr));

      sinaddr.sin_family = AF_INET;
      sinaddr.sin_port = htons(l_port);

      if (l_addr && SSH_IP_DEFINED(l_addr))
        SSH_IP4_ENCODE(l_addr, &sinaddr.sin_addr);

      ret = bind(listener->sock, (struct sockaddr *)&sinaddr,
                 (ssh_socklen_t) sizeof(sinaddr));
      if (ret == -1)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_make_ip4_listener: "
                                 "bind failed: %s", strerror(errno)));
          goto error;
        }
    }

  if ((r_addr && SSH_IP_DEFINED(r_addr)) || r_port != 0)
    {
      /* Initialize the address structure for the remote address. */
      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;
      sinaddr.sin_port = htons(r_port);

      if (r_addr && SSH_IP_DEFINED(r_addr))
        SSH_IP4_ENCODE(r_addr, &sinaddr.sin_addr);

      /* Mark the socket to be connected */
      listener->connected = TRUE;

      /* Connect the socket, so that we will receive unreachable
         notifications. */
      ret = connect(listener->sock, (struct sockaddr *)&sinaddr,
                    (ssh_socklen_t) sizeof(sinaddr));
      if (ret == -1)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_make_ip4_listener: connect failed: "\
                                 "%s", strerror(errno)));
          goto error;
        }
    }

  /* Set more common UDP socket options. */
  ssh_udp_set_more_common_socket_options(listener, params);

  /* Socket creation succeeded. Do the event loop stuff */
  if (ssh_io_register_fd(listener->sock, ssh_udp_io_cb,
                         (void *)listener) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_make_ip4_listener: "
                             "ssh_io_register_fd failed"));
      goto error;
    }

  ssh_io_set_fd_request(listener->sock, callback ? SSH_IO_READ : 0);

  return listener;

  /* Error handling. */
 error:

  if (listener != NULL)
    {
      if (listener->sock >= 0)
        close(listener->sock);
      ssh_free(listener);
    }

  return NULL;
}

#ifdef SSH_HAVE_IPV6

static void
ssh_udp_set_sockaddr_scope_id(SshUdpPlatformListener listener,
                              struct sockaddr_in6 *sinaddr,
                              SshScopeId id)
{
#ifdef HAVE_SOCKADDR_IN6_SCOPE_ID
  sinaddr->sin6_scope_id = id->scope_id_union.ui32;

  if (listener->scope_id_cached)
    sinaddr->sin6_scope_id = listener->cached_scope_id.scope_id_union.ui32;
#endif /* HAVE_SOCKADDR_IN6_SCOPE_ID  */
}

/* Creates an IPv6 UDP listener. */

static SshUdpPlatformListener
ssh_udp_make_ip6_listener(SshUdpListener generic_listener,
                          SshIpAddr l_addr, SshUInt16 l_port,
                          SshIpAddr r_addr, SshUInt16 r_port,
                          int interface_index,
                          int routing_instance_id,
                          SshUdpListenerParams params,
                          SshUdpCallback callback,
                          void *context)
{
  SshUdpPlatformListener listener;
  struct sockaddr_in6 sinaddr;
  int ret;

  /* Allocate and initialize the listener context. */
  listener = ssh_calloc(1, sizeof(*listener));
  if (listener == NULL)
    goto error;

  listener->listener = generic_listener;
  listener->ipv6 = TRUE;
  listener->context = context;
  listener->callback = callback;
  listener->connected = FALSE;

  /* Create the socket. */
  listener->sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (listener->sock == -1)
    goto error;

  /* Set the common socket options. */
  if (ssh_udp_set_common_socket_options(listener, params,
                                        routing_instance_id) == FALSE)
    goto error;





  if ((l_addr && SSH_IP_DEFINED(l_addr)) || l_port != 0)
    {
      /* Initialize the address structure for the local address. */
      memset(&sinaddr, 0, sizeof(sinaddr));

      sinaddr.sin6_family = AF_INET6;
      sinaddr.sin6_port = htons(l_port);

      if (l_addr && SSH_IP_DEFINED(l_addr))
        {
          SSH_IP6_ENCODE(l_addr, &sinaddr.sin6_addr);
          ssh_udp_set_sockaddr_scope_id(listener, &sinaddr, &l_addr->scope_id);

          /* Cache local scope into listener */
          listener->cached_scope_id = l_addr->scope_id;
          listener->scope_id_cached = TRUE;
        }

      ret = bind(listener->sock, (struct sockaddr *)&sinaddr,
                 (ssh_socklen_t) sizeof(sinaddr));
      if (ret == -1)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_make_ip6_listener: "
                                 "bind failed: %s", strerror(errno)));
          close(listener->sock);
          ssh_free(listener);
          return NULL;
        }
    }

  if ((r_addr && SSH_IP_DEFINED(r_addr)) || r_port != 0)
    {
      /* Initialize the address structure for the remote address. */
      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin6_family = AF_INET6;

      if (r_port != 0)
        sinaddr.sin6_port = htons(r_port);

      if (r_addr && SSH_IP_DEFINED(r_addr))
        {
          SSH_IP6_ENCODE(r_addr, &sinaddr.sin6_addr);
          ssh_udp_set_sockaddr_scope_id(listener, &sinaddr, &r_addr->scope_id);
        }

      /* Mark the socket to be connected */
      listener->connected = TRUE;

      /* Connect the socket, so that we will receive unreachable
         notifications. */
      ret = connect(listener->sock, (struct sockaddr *)&sinaddr,
                    (ssh_socklen_t) sizeof(sinaddr));
      if (ret == -1)
        {
          SSH_DEBUG(((errno != EHOSTUNREACH) ? SSH_D_FAIL : SSH_D_LOWOK),
                    ("ssh_udp_make_ip6_listener: connect failed: "\
                     "%s", strerror(errno)));
          goto error;
        }
    }

  /* Set more common UDP socket options. */
  ssh_udp_set_more_common_socket_options(listener, params);

  /* Socket creation succeeded. Do the event loop stuff */
  if (ssh_io_register_fd(listener->sock, ssh_udp_io_cb,
                         (void *)listener) == FALSE)
    goto error;
  ssh_io_set_fd_request(listener->sock, callback ? SSH_IO_READ : 0);

  return listener;


  /* Error handling. */

 error:

  if (listener)
    {
      if (listener->sock >= 0)
        close(listener->sock);
      ssh_free(listener);
    }

  return NULL;
}
#endif /* SSH_HAVE_IPV6 */

/* Creates a listener for sending and receiving UDP packets.  The listener is
   connected if remote_address is non-NULL.  Connected listeners may receive
   notifications about the destination host/port being unreachable.
     local_address       local address for sending; SSH_IPADDR_ANY chooses
                         automatically
     local_port          local port for receiving udp packets
     remote_address      specifies the remote address for this listener
                         is non-NULL.  If specified, unreachable notifications
                         may be received for packets sent to the address.
     remote_port         remote port for packets sent using this listener,
                         or NULL
     interface_index     speficies the interface index for this listener or -1
     routing_instance_id speficies the routing instance id for this listener
     params              additional paameters for the listener.  This can be
                         NULL in which case the default parameters are used.
     callback            function to call when packet or notification available
     context             argument to pass to the callback. */

static void *
ssh_udp_platform_make_listener(void *make_listener_method_context,
                               SshUdpListener listener,
                               SshIpAddr l_addr, SshUInt16 l_port,
                               SshIpAddr r_addr, SshUInt16 r_port,
                               int interface_index,
                               int routing_instance_id,
                               SshUdpListenerParams params,
                               SshUdpCallback callback,
                               void *context)
{
  SshUdpPlatformListener listener4 = NULL;
#ifdef SSH_HAVE_IPV6
  SshUdpPlatformListener listener6 = NULL;
#endif /* SSH_HAVE_IPV6 */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Making UDP listener"));

  /* Let's determine the type of listener to create. */
  if (l_addr && SSH_IP_DEFINED(l_addr))
    {
      if (SSH_IP_IS4(l_addr))
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv4 only UDP listener for address %@",
                     ssh_ipaddr_render, l_addr));
          return ssh_udp_make_ip4_listener(listener,
                                           l_addr, l_port, r_addr, r_port,
                                           interface_index,
                                           routing_instance_id,
                                           params,
                                           callback, context);
        }
      else
        {
#ifdef SSH_HAVE_IPV6
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv6 only UDP listener for address %@",
                     ssh_ipaddr_render, l_addr));
          return ssh_udp_make_ip6_listener(listener,
                                           l_addr, l_port, r_addr, r_port,
                                           interface_index,
                                           routing_instance_id,
                                           params,
                                           callback, context);
#else /* not  SSH_HAVE_IPV6 */
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("IPv6 is not supported on this platform"));
          return NULL;
#endif /* not SSH_HAVE_IPV6 */
        }
    }

  /* Let's determine the type of listener to create by the remote address. */
  if (r_addr && SSH_IP_DEFINED(r_addr))
    {
      if (SSH_IP_IS4(r_addr))
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv4 only UDP listener for address %@",
                     ssh_ipaddr_render, r_addr));
          return ssh_udp_make_ip4_listener(listener,
                                           l_addr, l_port, r_addr, r_port,
                                           interface_index,
                                           routing_instance_id,
                                           params,
                                           callback, context);
        }
      else
        {
#ifdef SSH_HAVE_IPV6
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv6 only UDP listener for address %@",
                     ssh_ipaddr_render, r_addr));
          return ssh_udp_make_ip6_listener(listener,
                                           l_addr, l_port, r_addr, r_port,
                                           interface_index,
                                           routing_instance_id,
                                           params,
                                           callback, context);
#else /* not  SSH_HAVE_IPV6 */
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("IPv6 is not supported on this platform"));
          return NULL;
#endif /* not SSH_HAVE_IPV6 */
        }
    }

  /* Create a dual listener for both IPv4 and IPv6. */
  SSH_DEBUG(SSH_D_HIGHSTART, ("Making IPv4 and IPv6 UDP listeners"));

  listener4 = ssh_udp_make_ip4_listener(listener,
                                        l_addr, l_port, r_addr, r_port,
                                        interface_index,
                                        routing_instance_id,
                                        params,
                                        callback, context);
  if (listener4 == NULL)
    return NULL;

#ifdef SSH_HAVE_IPV6
  /* Try to create an IPv6 listener.  It is ok if this fails since
     there seems to be systems which do not support IPv6 although they
     know the in6 structures. */
  listener6 = ssh_udp_make_ip6_listener(listener,
                                        l_addr, l_port, r_addr, r_port,
                                        interface_index,
                                        routing_instance_id,
                                        params,
                                        callback, context);
  if (listener6 != NULL)
    {
      /* We managed to make them both. */
      listener4->sibling = listener6;
    }
#endif /* SSH_HAVE_IPV6 */

  return listener4;
}

/* Destroys the udp listener. */

static void
ssh_udp_platform_destroy_listener(void *listener_context)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;

  if (listener->sibling)
    ssh_udp_platform_destroy_listener(listener->sibling);

  ssh_io_unregister_fd(listener->sock, TRUE);
  close(listener->sock);
  ssh_free(listener);
}

/* Reads the received packet or notification from the listener.  This
   function should be called from the listener callback.  This can be
   called multiple times from a callback; each call will read one more
   packet or notification from the listener until no more are
   available. */

static SshUdpError
ssh_udp_platform_read(void *listener_context,
                      SshIpAddr r_addr, SshUInt16 *r_port,
                      unsigned char *datagram_buffer,
                      size_t datagram_buffer_len,
                      size_t *datagram_len_return)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
  size_t ret;
  struct sockaddr_in from_addr4;
#ifdef SSH_HAVE_IPV6
  struct sockaddr_in6 from_addr6;
#endif /* SSH_HAVE_IPV6 */
  struct sockaddr *from_addr = NULL;
  int port = 0;
#ifndef VXWORKS
  ssh_socklen_t fromlen = 0L;
#ifndef __linux__
  ssh_socklen_t fromlen_min = 0L;
#endif
#else
  int fromlen = 0, fromlen_min = 0;
#endif

  if (datagram_len_return)
    *datagram_len_return = 0;

#ifdef SSH_HAVE_IPV6
  if (listener->ipv6)
    {
      from_addr = (struct sockaddr *) &from_addr6;
      fromlen = sizeof(from_addr6);
    }
#endif /* SSH_HAVE_IPV6 */
  if (!listener->ipv6)
    {
      from_addr = (struct sockaddr *) &from_addr4;
      fromlen = sizeof(from_addr4);
    }

#ifndef __linux__
  fromlen_min = fromlen;
#endif

  ret = recvfrom(listener->sock, (void *)datagram_buffer, datagram_buffer_len,
                 0, from_addr, &fromlen);
  if (ret == (size_t)-1)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Read result %ld, error = %s", (long)ret,
                                 strerror(errno)));
      switch (errno)
        {
#ifdef EHOSTDOWN
        case EHOSTDOWN:
#endif /* EHOSTDOWN */
#ifdef EHOSTUNREACH
        case EHOSTUNREACH:
#endif /* EHOSTUNREACH */
          return SSH_UDP_HOST_UNREACHABLE;

#ifdef ECONNREFUSED
        case ECONNREFUSED:
#endif /* ECONNREFUSED */
#ifdef ENOPROTOOPT
        case ENOPROTOOPT:
#endif /* ENOPROTOOPT */
          return SSH_UDP_PORT_UNREACHABLE;
        default:
          return SSH_UDP_NO_DATA;
        }
    }
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Read got %ld bytes", (long)ret));














#ifndef __linux__
  if (fromlen >= fromlen_min)
#endif /* __linux__ */
    {
      /* Format port number in user buffer. */
      if (r_port != NULL)
        {
#ifdef SSH_HAVE_IPV6
          if (listener->ipv6)
            port = ntohs(from_addr6.sin6_port);
#endif /* SSH_HAVE_IPV6 */
          if (!listener->ipv6)
            port = ntohs(from_addr4.sin_port);

          *r_port = port;
        }

      /* Format source address in user buffer. */
      if (r_addr != NULL)
        {
#ifdef SSH_HAVE_IPV6
          if (listener->ipv6)
            {
              SSH_IP6_DECODE(r_addr, &from_addr6.sin6_addr.s6_addr);

#ifdef __linux__
              {
                Boolean is_ipv4_mapped_address = TRUE;
                int i;

                /* IPv6 allows for mapping of ipv4 addresses
                   directly to IPv6 scope. For IKE purposes the
                   addresses are _not_ the same, and therefore
                   for now we simply change the addresses to IPv4
                   when they are really IPv4 - that is, match
                   mask

                   ::FFFF:0:0/96
                */
                for (i = 0 ; i < 10 ; i++)
                  if (r_addr->addr_data[i])
                    {
                      is_ipv4_mapped_address = FALSE;
                      break;
                    }
                for (/* EMPTY */; i < 11 ; i++)
                  if (r_addr->addr_data[i] != 0xff)
                    {
                      is_ipv4_mapped_address = FALSE;
                      break;
                    }
                if (is_ipv4_mapped_address)
                  SSH_IP4_DECODE(r_addr, &r_addr->addr_data[12]);
              }
#endif /* __linux__ */
            }
#endif /* SSH_HAVE_IPV6 */
          if (!listener->ipv6)
            SSH_IP4_DECODE(r_addr, &from_addr4.sin_addr.s_addr);
        }
    }

  /* Return the length of the received packet. */
  if (datagram_len_return)
    *datagram_len_return = ret;

  return SSH_UDP_OK;
}

/* This sends udp datagram to remote destination. This call always success, or
   the if not then datagram is silently dropped (udp is not reliable anyways */

static SshUdpError
ssh_udp_platform_send(void *listener_context,
                      SshIpAddr r_addr, SshUInt16 r_port,
                      const unsigned char *datagram_buffer,
                      size_t datagram_len)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
  struct sockaddr *to_addr;
  ssh_socklen_t to_addr_len;
  struct sockaddr_in to_addr4;
#ifdef SSH_HAVE_IPV6
      struct sockaddr_in6 to_addr6;
#endif /* SSH_HAVE_IPV6 */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Send %zd bytes to %@;%d", datagram_len,
                               ssh_ipaddr_render, r_addr, r_port));

  if (listener->connected)
    {
      if (r_port != 0)
        SSH_DEBUG(SSH_D_FAIL,
                  ("ssh_udp_platform_send: Remote port number `%d' specified "
                   "for connected socket, ignored", r_port));
      if (r_addr && SSH_IP_DEFINED(r_addr))
        SSH_DEBUG(SSH_D_FAIL,
                  ("ssh_udp_platform_send: Remote address `%@' specified for "
                   "connected socket, ignored",
                   ssh_ipaddr_render, r_addr));

      /* Send the packet to the connected socket. */
      if (send(listener->sock, (void *)datagram_buffer, datagram_len,
               0) == -1)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_platform_send: send failed: %s",
                                 strerror(errno)));
          return SSH_UDP_INVALID_ARGUMENTS;
        }
      return SSH_UDP_OK;
    }

  if (SSH_IP_IS6(r_addr))
    {
      /* IPv6 addresses. */
#ifdef SSH_HAVE_IPV6
      /* Do we have an IPv6 listener? */
      if (listener->ipv6)
        ;
      else if (listener->sibling && listener->sibling->ipv6)
        listener = listener->sibling;
      else
        {
          /* We do not have it. */
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_platform_send: no IPv6 listener"));
          return SSH_UDP_INVALID_ARGUMENTS;
        }

      memset(&to_addr6, 0, sizeof(to_addr6));
      to_addr6.sin6_family = AF_INET6;
      to_addr6.sin6_port = htons(r_port);
      SSH_IP6_ENCODE(r_addr, &to_addr6.sin6_addr);
      ssh_udp_set_sockaddr_scope_id(listener, &to_addr6, &r_addr->scope_id);

      to_addr = (struct sockaddr *) &to_addr6;
      to_addr_len = sizeof(to_addr6);

#else /* not SSH_HAVE_IPV6 */
      SSH_DEBUG(SSH_D_FAIL, ("IPv6 is not supported on this platform"));
      return SSH_UDP_INVALID_ARGUMENTS;
#endif /* SSH_HAVE_IPV6 */
    }
  else
    {
      /* IPv4 and unspecified remote address cases. */
      memset(&to_addr4, 0, sizeof(to_addr));
      to_addr4.sin_family = AF_INET;
      to_addr4.sin_port = htons(r_port);

      if (r_addr && SSH_IP_DEFINED(r_addr))
        SSH_IP4_ENCODE(r_addr, &to_addr4.sin_addr);

      to_addr = (struct sockaddr *) &to_addr4;
      to_addr_len = sizeof(to_addr4);
    }

  /* Send the packet. */
  if (sendto(listener->sock, (void *)datagram_buffer, datagram_len, 0,
             to_addr, to_addr_len) == -1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_platform_send: sendto failed: %s",
                             strerror(errno)));
      return SSH_UDP_INVALID_ARGUMENTS;
    }

  return SSH_UDP_OK;
}

/* Add membership to given multicast group */

static SshUdpError
ssh_udp_platform_multicast_add_membership(void *listener_context,
                                          SshIpAddr group_to_join,
                                          SshIpAddr interface_to_join)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;

  for (; listener; listener = listener->sibling)
    {
#ifdef SSH_HAVE_IPV6_MULTICAST
      if (listener->ipv6)
        {
          struct ipv6_mreq mreq6;

          memset(&mreq6, 0, sizeof(mreq6));

          SSH_IP6_ENCODE(group_to_join,
                         (unsigned char *)&(mreq6.ipv6mr_multiaddr.s6_addr));

          if (interface_to_join && SSH_IP_DEFINED(interface_to_join))
            {



            }
          if (!setsockopt(listener->sock,
                          IPPROTO_IPV6,
                          IPV6_JOIN_GROUP,
                          (void *)&mreq6,
                          (ssh_socklen_t) sizeof(mreq6)))
            {
              return SSH_UDP_OK;
            }
        }
      else
#endif /* SSH_HAVE_IPV6_MUILTICAST */
        {
#ifdef IP_ADD_MEMBERSHIP
          struct ip_mreq mreq;

          memset(&mreq, 0, sizeof(mreq));

          SSH_IP4_ENCODE(group_to_join,
                         (unsigned char *)&(mreq.imr_multiaddr.s_addr));

          if (interface_to_join && SSH_IP_DEFINED(interface_to_join))
            {
              SSH_IP4_ENCODE(interface_to_join,
                             (unsigned char *)&(mreq.imr_interface.s_addr));
            }
          if (!setsockopt(listener->sock,
                          IPPROTO_IP,
                          IP_ADD_MEMBERSHIP,
                          (void *)&mreq,
                          (ssh_socklen_t) sizeof(mreq)))
            {
              return SSH_UDP_OK;
            }
#else /* IP_ADD_MEMBERSHIP */
          continue;
#endif /* IP_ADD_MEMBERSHIP */
        }
    }
  return SSH_UDP_INVALID_ARGUMENTS;
}

/* Drop membership to given multicast group */

static SshUdpError
ssh_udp_platform_multicast_drop_membership(void *listener_context,
                                           SshIpAddr group_to_drop,
                                           SshIpAddr interface_to_drop)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;

  for (; listener; listener = listener->sibling)
    {
#ifdef SSH_HAVE_IPV6_MULTICAST
      if (listener->ipv6)
        {
          struct ipv6_mreq mreq6;

          memset(&mreq6, 0, sizeof(mreq6));

          SSH_IP6_ENCODE(group_to_drop,
                         (unsigned char *)&(mreq6.ipv6mr_multiaddr.s6_addr));
          if (interface_to_drop && SSH_IP_DEFINED(interface_to_drop))
            {



            }
          (void)setsockopt(listener->sock,
                           IPPROTO_IPV6,
                           IPV6_LEAVE_GROUP,
                           (void *)&mreq6,
                           (ssh_socklen_t) sizeof(mreq6));
        }
      else
#endif /* SSH_HAVE_IPV6_MULTICAST */
        {
#ifdef IP_DROP_MEMBERSHIP
          struct ip_mreq mreq;

          memset(&mreq, 0, sizeof(mreq));

          SSH_IP4_ENCODE(group_to_drop,
                         (unsigned char *)&(mreq.imr_multiaddr.s_addr));

          if (interface_to_drop && SSH_IP_DEFINED(interface_to_drop))
            {
              SSH_IP4_ENCODE(interface_to_drop,
                             (unsigned char *)&(mreq.imr_interface.s_addr));
            }
          (void)setsockopt(listener->sock,
                           IPPROTO_IP,
                           IP_DROP_MEMBERSHIP,
                           (void *)&mreq,
                           (ssh_socklen_t) sizeof(mreq));
#else /* IP_DROP_MEMBERSHIP */
          continue;
#endif /* IP_DROP_MEMBERSHIP */
        }
    }
  return SSH_UDP_OK;
}

Boolean
ssh_udp_platform_get_ip_addresses(void *listener_context,
                                  SshIpAddr local_ip,
                                  SshUInt16 *local_port,
                                  SshIpAddr remote_ip,
                                  SshUInt16 *remote_port)
{
  SshUdpPlatformListener listener = (SshUdpPlatformListener) listener_context;
#ifdef HAVE_SOCKADDR_IN6_STRUCT
  struct sockaddr_in6 saddr;
#else /* HAVE_SOCKADDR_IN6_STRUCT */
  struct sockaddr_in saddr;
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
#ifndef VXWORKS
  ssh_socklen_t saddrlen;
#else
  int saddrlen;
#endif

  if (listener->sock == -1)
    return FALSE;

  if (remote_ip || remote_port)
    {
      saddrlen = sizeof(saddr);
      if (getpeername(listener->sock, (struct sockaddr *)&saddr, &saddrlen)
          < 0)
        return FALSE;

#ifdef HAVE_SOCKADDR_IN6_STRUCT
      if (remote_ip)
        {
          if (saddr.sin6_family == AF_INET6)
            SSH_IP6_DECODE(remote_ip, saddr.sin6_addr.s6_addr);
          else
            SSH_INT_TO_IP4(remote_ip,
                           htonl(((struct sockaddr_in*)&saddr)->
                                 sin_addr.s_addr));
          ssh_inet_convert_ip6_mapped_ip4_to_ip4(remote_ip);
        }
      if (remote_port)
        *remote_port = ntohs(saddr.sin6_port);
#else /* HAVE_SOCKADDR_IN6_STRUCT */
      if (remote_ip)
        {
          SSH_INT_TO_IP4(remote_ip,
                         htonl(((struct sockaddr_in*)&saddr)->
                               sin_addr.s_addr));
        }
      if (remote_port)
        *remote_port = ntohs(saddr.sin_port);
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }

   if (local_ip || local_port)
    {
      saddrlen = sizeof(saddr);
      if (getsockname(listener->sock, (struct sockaddr *)&saddr, &saddrlen)
          < 0)
        return FALSE;

#ifdef HAVE_SOCKADDR_IN6_STRUCT
      if (local_ip)
        {
          if (saddr.sin6_family == AF_INET6)
            SSH_IP6_DECODE(local_ip, saddr.sin6_addr.s6_addr);
          else
            SSH_INT_TO_IP4(local_ip,
                           htonl(((struct sockaddr_in*)&saddr)->
                                 sin_addr.s_addr));
          ssh_inet_convert_ip6_mapped_ip4_to_ip4(local_ip);
        }
      if (local_port)
        *local_port = ntohs(saddr.sin6_port);
#else /* HAVE_SOCKADDR_IN6_STRUCT */
      if (local_ip)
        {
          SSH_INT_TO_IP4(local_ip,
                         htonl(((struct sockaddr_in*)&saddr)->
                               sin_addr.s_addr));
        }
      if (local_port)
        *local_port = ntohs(saddr.sin_port);
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }

  return TRUE;
}

/* Platform dependent UDP methods. */
static const SshUdpMethodsStruct ssh_udp_methods =
{
  ssh_udp_platform_make_listener,
  ssh_udp_platform_destroy_listener,
  ssh_udp_platform_read,
  ssh_udp_platform_send,
  ssh_udp_platform_multicast_add_membership,
  ssh_udp_platform_multicast_drop_membership,
  ssh_udp_platform_get_ip_addresses,
};

/* Fetch the platform dependent UDP methods and constructor
   context. */

SshUdpMethods
ssh_udp_platform_methods(void **constructor_context_return)
{
  *constructor_context_return = NULL;
  return (SshUdpMethods) &ssh_udp_methods;
}
