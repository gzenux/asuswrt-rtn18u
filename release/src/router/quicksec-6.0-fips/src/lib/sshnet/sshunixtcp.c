/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Unix-specific code for sockets.
*/

#include "sshincludes.h"
#include "sshstream.h"
#include "sshnameserver.h"
#include "sshtcp.h"
#include "sshfdstream.h"
#include "ssheloop.h"

#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTM_H */
#if !defined(__PARAGON__)
#include <netinet/ip.h>
#endif /* !__PARAGON__ */
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */

#if !defined(HAVE_GETHOSTNAME)
# if defined(HAVE_UNAME) && defined(HAVE_SYS_UTSNAME_H)
#  include <sys/utsname.h>
# endif
#endif

#if defined(HAVE_SOCKADDR_IN6_STRUCT) && defined(WITH_IPV6)
/* Currently, we include the IPv6 code only if we have the
   `sockaddr_in6' structure. */
#define SSH_HAVE_IPV6
#ifdef IPV6_JOIN_GROUP
#define SSH_HAVE_IPV6_MULTICAST
#endif /* IPV6_JOIN_GROUP */
#endif /* HAVE_SOCKADDR_IN6_STRUCT && WITH_IPV6 */

#define SSH_DEBUG_MODULE "SshUnixTcp"

typedef struct LowConnectRec
{
  SshIOHandle sock;
  unsigned int port;
  SshTcpCallback callback;
  void *context;
  SshIpAddrStruct ipaddr;
  SshOperationHandle handle;
  int access_handle;

} *LowConnect;

static void
ssh_socket_low_bind_to_any(LowConnect c)
{
  SshIpAddr remote_address = &c->ipaddr;
  int sock = c->sock;

  if (remote_address && SSH_IP_IS4(remote_address))
    {
      struct sockaddr_in sinaddr;

      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;

      if (bind(sock, (struct sockaddr *) &sinaddr,
               (ssh_socklen_t) sizeof(sinaddr)) < 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
        }
    }
  else
  if (remote_address && SSH_IP_IS6(remote_address))
    {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
      struct sockaddr_in6 sinaddr6;

      memset(&sinaddr6, 0, sizeof(sinaddr6));
      sinaddr6.sin6_family = AF_INET6;

      if (bind(sock, (struct sockaddr *)&sinaddr6,
               (ssh_socklen_t) sizeof(sinaddr6)) < 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
        }
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }
}


static int
ssh_socket_low_get_port(LowConnect c)
{
  union
  {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  }
  sa;
  socklen_t len = sizeof sa;
  int port;

  if (getsockname(c->sock, (void *) &sa, &len) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("getsockename() failed."));
    }

  if (sa.in.sin_family == AF_INET)
    {
      port = ntohs(sa.in.sin_port);
    }
  else
    {
      port = ntohs(sa.in6.sin6_port);
    }

  return port;
}


void
ssh_socket_low_access_request(LowConnect c)
{
  int port;

  port = ssh_socket_low_get_port(c);
  if (port == 0)
    {
      ssh_socket_low_bind_to_any(c);

      port = ssh_socket_low_get_port(c);
    }

  if (port == 0)
    {
      port = -1;
    }

  if (c->access_handle == -1)
    {
      c->access_handle =
          ssh_inet_make_access_request_callback(
                  NULL,
                  &c->ipaddr,
                  6,
                  port,
                  c->port);
    }
}


void
ssh_socket_low_access_update(LowConnect c)
{
  union
  {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
  }
  sa;
  socklen_t len = sizeof sa;
  SshIpAddrStruct ipaddr;
  int port;

  if (c->access_handle != -1)
    {
      ssh_inet_make_access_release_callback(
              c->access_handle,
              1);
      c->access_handle = -1;
    }

  if (getsockname(c->sock, (void *) &sa, &len) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("getsockename() failed."));
    }

  if (sa.in.sin_family == AF_INET)
    {
      SSH_IP4_DECODE(&ipaddr, &sa.in.sin_addr);
      port = ntohs(sa.in.sin_port);
    }
  else
    {
      SSH_IP6_DECODE(&ipaddr, &sa.in6.sin6_addr);
      port = ntohs(sa.in6.sin6_port);
    }

  c->access_handle =
      ssh_inet_make_access_request_callback(
              &ipaddr,
              &c->ipaddr,
              6,
              port,
              c->port);
}

void
ssh_socket_low_access_release(LowConnect c)
{
  ssh_inet_make_access_release_callback(
          c->access_handle,
          0);
}


static LowConnect
ssh_tcp_low_connect_init(void)
{
  LowConnect c;

  c = ssh_calloc(1, sizeof(*c));

  if (c != NULL)
    {
      c->access_handle = -1;
    }

  return c;
}

static void
ssh_tcp_low_connect_free(LowConnect c)
{
  if (c->access_handle != -1)
    {
      ssh_socket_low_access_release(c);
    }

  ssh_free(c);
}

static int
ssh_tcp_create_socket(SshIpAddr address)
{
  Boolean ok = FALSE;
  Boolean ip6;
  int sock = -1;

  if (SSH_IP_IS6(address))
    {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
      ip6 = TRUE;
      ok = TRUE;
 #endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }
  else if (SSH_IP_IS4(address))
    {
      ip6 = FALSE;
      ok = TRUE;
    }

  /* Create a socket. */
  if (ok == TRUE)
    {
      sock = ssh_tcp_make_socket_request_callback(ip6);
      if (sock < 0)
        {
          if (ip6 == TRUE)
            {
              sock = socket(AF_INET6, SOCK_STREAM, 0);
            }
          else
            {
              sock = socket(AF_INET, SOCK_STREAM, 0);
            }
        }
    }

  return sock;
}

static void
ssh_tcp_close_socket(int sock)
{
  if (ssh_tcp_make_socket_release_callback(sock) < 0)
    close(sock);
}


typedef struct SshTcpCloseContextRec
{
  int sock;
  int access_handle;

} SshTcpCloseContextStruct, *SshTcpCloseContext;

static void
tcp_stream_close_callback(void *param)
{
  SshTcpCloseContext close_context = param;

  if (close_context != NULL)
    {
      ssh_inet_make_access_release_callback(
              close_context->access_handle,
              SSH_INET_TCP_ACCESS_DELAY);

      ssh_tcp_close_socket(close_context->sock);

      ssh_free(close_context);
    }
}

static SshStream
ssh_tcp_stream_create(LowConnect c)
{
  SshTcpCloseContext close_context;
  SshStream str = NULL;

  close_context = ssh_calloc(1, sizeof(*close_context));
  if (close_context != NULL)
    {
      close_context->sock = c->sock;
      close_context->access_handle = c->access_handle;

      str = ssh_stream_fd_wrap_with_close_callback(
              c->sock,
              tcp_stream_close_callback,
              close_context,
              FALSE);
      if (str == NULL)
        {
          ssh_free(close_context);
        }
    }

  return str;
}

SshTcpConnectMethods
ssh_tcp_connect_platform_methods(void **constructor_context_return);

#if !defined(HAVE_GETSERVBYNAME) && defined(WANT_SERVBYNAME)\
 || !defined(HAVE_GETSERVBYPORT) && defined(WANT_SERVBYPORT)

/* that exports __global_table[] as "root" of data */
#include "sshgetservbyname_servicetable.c"

/* done a a define here, so comparison can be turned to
   case-insignificant if needed, first argument should
   rather be the statically allocated string to assure
   that we don't read far past the user string if it
   somehow happens to be non-terminated.
  */
#define GETSERV_STRCMP(x,y) strncmp((x), (y), strlen(x)+1)

static Boolean find_in_aliases(char const * const * const aliases,
                               char const * const name)
{
  int i;
  for (i = 0; ; i++)
    {
      if (aliases[i]==NULL) return FALSE;
      if (GETSERV_STRCMP(aliases[i], name)==0) return TRUE;
    }
}

static struct SshServent const *
ssh_getserv(const char* name, int port, Boolean byname, const char* protocol)
{
  int i;
  int k;

  for (i = 0; ; i++)
    {
      if (__global_table[i].protocol == NULL)
        return NULL;
      if (protocol != NULL &&
          GETSERV_STRCMP(__global_table[i].protocol, protocol)!=0)
        continue;
      /* search item in list for this protocol */
      for (k = 0; ; k++)
        {
          if ((byname!=FALSE)
              ? find_in_aliases(__global_table[i].table[k].s_aliases, name)
              : __global_table[i].table[k].s_port == port )
            return &(__global_table[i].table[k]);
        }
    }
}

#endif /* SERVBYNAME */

void ssh_socket_set_reuseaddr(int sock)
{
#ifdef SO_REUSEADDR
  int on = 1;
  (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                   (ssh_socklen_t) sizeof(on));
#endif /* SO_REUSEADDR */
}

void ssh_socket_set_reuseport(int sock)
{
#ifdef SO_REUSEPORT
  int on = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *)&on,
             (ssh_socklen_t) sizeof(on));
#endif /* SO_REUSEPORT */
}

#ifdef NO_NONBLOCKING_CONNECT


SshOperationHandle ssh_socket_low_connect_try_once(unsigned int events,
                                                   void *context)
{
  LowConnect c = (LowConnect)context;
  int ret = -1;
  SshTcpError error;

  ssh_socket_low_access_request(c);

  if (SSH_IP_IS6(&c->ipaddr))
    {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
      struct sockaddr_in6 sinaddr6;

      memset(&sinaddr6, 0, sizeof(sinaddr6));
      sinaddr6.sin6_family = AF_INET6;
      sinaddr6.sin6_port = htons(c->port);
      memcpy(sinaddr6.sin6_addr.s6_addr, c->ipaddr.addr_data, 16);

      /* Make a blocking connect attempt. */
      ret = connect(c->sock, (struct sockaddr *)&sinaddr6,
                    (ssh_socklen_t) sizeof(sinaddr6));
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }
  else
    {
      struct sockaddr_in sinaddr;

      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;
      sinaddr.sin_port = htons(c->port);
      sinaddr.sin_addr.s_addr = htonl(SSH_IP4_TO_INT(&(c->ipaddr)));

      /* Make a blocking connect attempt. */
      ret = connect(c->sock, (struct sockaddr *)&sinaddr,
                    (ssh_socklen_t) sizeof(sinaddr));
    }

  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      SshStream str;

      ssh_socket_low_access_update(c);

      str = ssh_tcp_stream_create(c);

      if (str == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("Insufficient memory to create TCP stream."));
          ssh_tcp_close_socket(c->sock);
          (*c->callback)(SSH_TCP_FAILURE,NULL,c->context);
          ssh_tcp_low_connect_free(c);
          return NULL;
        }

      c->access_handle = -1;

      /* Successful connection. */
      ssh_stream_set_private_methods(str,
                              (void *) ssh_tcp_connect_platform_methods(NULL));

      (*c->callback)(SSH_TCP_OK, str, c->context);
      ssh_tcp_low_connect_free(c);
      return NULL;
    }

  /* Connection failed. */
  SSH_DEBUG(5, ("Connect failed: %s", strerror(errno)));
  error = SSH_TCP_FAILURE;
#ifdef ENETUNREACH
  if (errno == ENETUNREACH)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ECONNREFUSED
  if (errno == ECONNREFUSED)
    error = SSH_TCP_REFUSED;
#endif
#ifdef EHOSTUNREACH
  if (errno == EHOSTUNREACH)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ENETDOWN
  if (errno == ENETDOWN)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ETIMEDOUT
  if (errno == ETIMEDOUT)
    error = SSH_TCP_TIMEOUT;
#endif

  ssh_tcp_close_socket(c->sock);
  (*c->callback)(error, NULL, c->context);
  ssh_tcp_low_connect_free(c);
  return NULL;
}

#else /* NO_NONBLOCKING_CONNECT */

/* Connection aborted out */
void ssh_tcp_low_connect_aborted(void *context)
{
  LowConnect c = (LowConnect)context;

  ssh_io_unregister_fd(c->sock, FALSE);
  ssh_tcp_close_socket(c->sock);

  ssh_tcp_low_connect_free(c);
}

SshOperationHandle ssh_socket_low_connect_try(unsigned int events,
                                              void *context)
{
  LowConnect c = (LowConnect)context;
  int ret = 1;
  SshTcpError error;

  ssh_socket_low_access_request(c);

  if (SSH_IP_IS6(&(c->ipaddr)))
    {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
      struct sockaddr_in6 sinaddr6;

      memset(&sinaddr6, 0, sizeof(sinaddr6));
      sinaddr6.sin6_family = AF_INET6;
      sinaddr6.sin6_port = htons(c->port);
      memcpy(sinaddr6.sin6_addr.s6_addr, c->ipaddr.addr_data, 16);

      /* Make a non-blocking connect attempt. */
      ret = connect(c->sock, (struct sockaddr *)&sinaddr6,
                    (ssh_socklen_t) sizeof(sinaddr6));
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }
  else
    {
      struct sockaddr_in sinaddr;

      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;
      sinaddr.sin_port = htons(c->port);
      sinaddr.sin_addr.s_addr = htonl(SSH_IP4_TO_INT(&(c->ipaddr)));

      /* Make a non-blocking connect attempt. */
      ret = connect(c->sock, (struct sockaddr *)&sinaddr,
                    (ssh_socklen_t) sizeof(sinaddr));
    }

  if (ret >= 0 || errno == EISCONN) /* Connection is ready. */
    {
      SshStream str;

      /* Successful connection. */
      ssh_io_unregister_fd(c->sock, FALSE);

      ssh_socket_low_access_update(c);

      str = ssh_tcp_stream_create(c);

      if (str == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("Insufficient memory to create TCP stream."));
          ssh_tcp_close_socket(c->sock);

          ssh_inet_make_access_release_callback(
                  c->access_handle,
                  SSH_INET_TCP_ACCESS_DELAY);

          (*c->callback)(SSH_TCP_FAILURE, NULL, c->context);
        }
      else
        {
          c->access_handle = -1;

          ssh_stream_set_private_methods(str,
                              (void *) ssh_tcp_connect_platform_methods(NULL));
          (*c->callback)(SSH_TCP_OK, str, c->context);
        }
      if (c->handle)
        ssh_operation_unregister(c->handle);
      ssh_tcp_low_connect_free(c);
      return NULL;
    }
  if (errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EALREADY)
    {
      /* Connection still in progress.  */
      ssh_io_set_fd_request(c->sock, SSH_IO_WRITE);

      if (!c->handle)
        c->handle = ssh_operation_register(ssh_tcp_low_connect_aborted, c);

      return c->handle;
    }

  SSH_DEBUG(5, ("Connect failed: %s", strerror(errno)));
  /* Connection failed. */
  error = SSH_TCP_FAILURE;
#ifdef ENETUNREACH
  if (errno == ENETUNREACH)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ECONNREFUSED
  if (errno == ECONNREFUSED)
    error = SSH_TCP_REFUSED;
#endif
#ifdef EHOSTUNREACH
  if (errno == EHOSTUNREACH)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ENETDOWN
  if (errno == ENETDOWN)
    error = SSH_TCP_UNREACHABLE;
#endif
#ifdef ETIMEDOUT
  if (errno == ETIMEDOUT)
    error = SSH_TCP_TIMEOUT;
#endif

  ssh_io_unregister_fd(c->sock, FALSE);
  ssh_tcp_close_socket(c->sock);

  (*c->callback)(error, NULL, c->context);
  if (c->handle)
    ssh_operation_unregister(c->handle);

  ssh_tcp_low_connect_free(c);

  return NULL;
}

#endif /* NO_NONBLOCKING_CONNECT */

/* Connects to the given address/port, and makes a stream for it. */

SshOperationHandle ssh_tcp_low_connect_ip(void *connect_method_context,
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
  SshIOHandle sock = -1;
  LowConnect c;

  /* Save data in a context structure. */
  if ((c = ssh_tcp_low_connect_init()) == NULL)
    {
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  c->port = remote_port;
  c->callback = callback;
  c->context = context;
  c->ipaddr = *(remote_address);
  c->handle = NULL;

  /* Create a socket. */
  sock = ssh_tcp_create_socket(&(c->ipaddr));
  if (sock < 0)
    {
      ssh_tcp_low_connect_free(c);

      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  c->sock = sock;

  switch (params ? params->local_reusable : SSH_TCP_REUSABLE_ADDRESS)
    {
    case SSH_TCP_REUSABLE_PORT:
      ssh_socket_set_reuseport(sock);
      break;

    case SSH_TCP_REUSABLE_ADDRESS:
      ssh_socket_set_reuseaddr(sock);
      break;

    case SSH_TCP_REUSABLE_BOTH:
      ssh_socket_set_reuseport(sock);
      ssh_socket_set_reuseaddr(sock);
      break;

    case SSH_TCP_REUSABLE_NONE:
      break;

    }

  /* Bind local end if requested. */
  if ((local_address && SSH_IP_DEFINED(local_address)) || local_port)
    {
      if ((local_address && SSH_IP_IS4(local_address)) ||
          ((local_address == NULL || !SSH_IP_DEFINED(local_address))
           && SSH_IP_IS4((&(c->ipaddr)))))
        {
          struct sockaddr_in sinaddr;

          memset(&sinaddr, 0, sizeof(sinaddr));
          sinaddr.sin_family = AF_INET;
          sinaddr.sin_port = htons(local_port);
          if (local_address)
            sinaddr.sin_addr.s_addr = htonl(SSH_IP4_TO_INT(local_address));
          if (bind(sock, (struct sockaddr *) &sinaddr,
                   (ssh_socklen_t) sizeof(sinaddr)) < 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
            error_local:
              ssh_tcp_close_socket(sock);
              ssh_tcp_low_connect_free(c);

              (*callback)(SSH_TCP_FAILURE, NULL, context);
              return NULL;
            }
        }
      else if ((local_address && SSH_IP_IS6(local_address)) ||
               ((local_address == NULL || !SSH_IP_DEFINED(local_address))
                && SSH_IP_IS6(&(c->ipaddr))))
      {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
          struct sockaddr_in6 sinaddr6;

          memset(&sinaddr6, 0, sizeof(sinaddr6));
          sinaddr6.sin6_family = AF_INET6;
          sinaddr6.sin6_port = htons(local_port);
          if (local_address)
            memcpy(sinaddr6.sin6_addr.s6_addr, c->ipaddr.addr_data, 16);
          if (bind(sock, (struct sockaddr *)&sinaddr6,
                   (ssh_socklen_t) sizeof(sinaddr6)) < 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
              goto error_local;
            }
#else /* HAVE_SOCKADDR_IN6_STRUCT */
          SSH_DEBUG(SSH_D_ERROR, ("No sockaddr_in6 structure"));
          goto error_local;
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid local address `%@'",
                                  ssh_ipaddr_render, local_address));
          goto error_local;
        }
    }

#ifdef NO_NONBLOCKING_CONNECT

  /* Try connect once.  Function calls user callback. */
  return ssh_socket_low_connect_try_once(SSH_IO_WRITE, (void *)c);

#else /* NO_NONBLOCKING_CONNECT */

  /* Register it and request events. */
  if (ssh_io_register_fd(sock,
                         (void (*)(unsigned int events, void *context))
                         ssh_socket_low_connect_try, (void *)c)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,("Failed to register file descriptor!"));
      goto error_local;
    }
  ssh_io_set_fd_request(sock, SSH_IO_WRITE);

  /* Fake a callback to start asynchronous connect. */
  return ssh_socket_low_connect_try(SSH_IO_WRITE, (void *)c);

#endif /* NO_NONBLOCKING_CONNECT */
}

/* Connects to the given address/port, and makes a stream for it.
   The address to use is the first address from the list. */

SshOperationHandle ssh_socket_low_connect(
                                void *connect_method_context,
                                const unsigned char *local_address,
                                unsigned int local_port,
                                SshTcpReusableType local_reusable,
                                const unsigned char *address_list,
                                unsigned int port,
                                int interface_index,
                                int routing_instance_id,
                                SshTcpConnectParams params,
                                SshTcpCallback callback,
                                void *context)
{
  SshIOHandle sock = -1;
  int first_len;
  LowConnect c;
  unsigned char *tmp;

  /* Save data in a context structure. */
  if ((c = ssh_tcp_low_connect_init()) == NULL)
    {
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  /* Compute the length of the first address on the list. */
  if (ssh_ustrchr(address_list, ','))
    first_len = ssh_ustrchr(address_list, ',') - address_list;
  else
    first_len = ssh_ustrlen(address_list);

  tmp = ssh_memdup(address_list, first_len);

  if (!tmp || !ssh_ipaddr_parse(&(c->ipaddr), tmp))
    {
      ssh_free(tmp);
      ssh_tcp_low_connect_free(c);
      (*callback)(SSH_TCP_NO_ADDRESS, NULL, context);
      return NULL;
    }

  ssh_free(tmp);

  /* Create a socket. */
  sock = ssh_tcp_create_socket(&(c->ipaddr));
  if (sock < 0)
    {
      ssh_tcp_low_connect_free(c);
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  switch (local_reusable)
    {
    case SSH_TCP_REUSABLE_PORT:
      ssh_socket_set_reuseport(sock);
      break;

    case SSH_TCP_REUSABLE_ADDRESS:
      ssh_socket_set_reuseaddr(sock);
      break;

    case SSH_TCP_REUSABLE_BOTH:
      ssh_socket_set_reuseport(sock);
      ssh_socket_set_reuseaddr(sock);
      break;

    case SSH_TCP_REUSABLE_NONE:
      break;

    }

  /* Bind local end if requested. */
  if (local_address || local_port)
    {
      SshIpAddrStruct ipaddr;

      if (local_address == NULL || SSH_IS_IPADDR_ANY(local_address))
        {
          if (SSH_IP_IS4(&c->ipaddr))
            local_address = ssh_custr(SSH_IPADDR_ANY_IPV4);
          else
            local_address = ssh_custr(SSH_IPADDR_ANY_IPV6);
        }

      if (!ssh_ipaddr_parse(&ipaddr, local_address))
        {
        error_local:
          ssh_tcp_close_socket(sock);
          ssh_tcp_low_connect_free(c);
          (*callback)(SSH_TCP_FAILURE, NULL, context);
          return NULL;
        }

      if (SSH_IP_IS4(&ipaddr))
        {
          struct sockaddr_in sinaddr;

          memset(&sinaddr, 0, sizeof(sinaddr));
          sinaddr.sin_family = AF_INET;
          sinaddr.sin_port = htons(local_port);

#ifdef BROKEN_INET_ADDR
          sinaddr.sin_addr.s_addr =
            (unsigned long)(inet_network(ssh_csstr(local_address)));
#else /* BROKEN_INET_ADDR */
          sinaddr.sin_addr.s_addr =
            (unsigned long)(inet_addr((char *)ssh_csstr(local_address)));
#endif /* BROKEN_INET_ADDR */
          if ((sinaddr.sin_addr.s_addr & 0xffffffff) == 0xffffffff)
            goto error_local;

          if (bind(sock, (struct sockaddr *) &sinaddr,
                   (ssh_socklen_t) sizeof(sinaddr)) < 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
              goto error_local;
            }
        }
      else if (SSH_IP_IS6(&ipaddr))
        {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
          struct sockaddr_in6 sinaddr6;

          memset(&sinaddr6, 0, sizeof(sinaddr6));
          sinaddr6.sin6_family = AF_INET6;
          sinaddr6.sin6_port = htons(local_port);
          SSH_IP6_ENCODE(&ipaddr, sinaddr6.sin6_addr.s6_addr);

          if (bind(sock, (struct sockaddr *)&sinaddr6,
                   (ssh_socklen_t) sizeof(sinaddr6)) < 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Bind failed: %s", strerror(errno)));
              goto error_local;
            }
#else /* HAVE_SOCKADDR_IN6_STRUCT */
          SSH_DEBUG(SSH_D_ERROR, ("No sockaddr_in6 structure"));
          goto error_local;
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not parse local address `%s'",
                                  local_address));
          goto error_local;
        }
    }

  c->sock = sock;
  c->port = port;
  c->callback = callback;
  c->context = context;
  c->handle = NULL;

#ifdef NO_NONBLOCKING_CONNECT

  /* Try connect once.  Function calls user callback. */
  return ssh_socket_low_connect_try_once(SSH_IO_WRITE, (void *)c);

#else /* NO_NONBLOCKING_CONNECT */

  /* Register it and request events. */
  if (ssh_io_register_fd(sock,
                         (void (*)(unsigned int events, void *context))
                         ssh_socket_low_connect_try, (void *)c)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,("Failed to register file descriptor!"));
      goto error_local;
    }
  ssh_io_set_fd_request(sock, SSH_IO_WRITE);

  /* Fake a callback to start asynchronous connect. */
  return ssh_socket_low_connect_try(SSH_IO_WRITE, (void *)c);

#endif /* NO_NONBLOCKING_CONNECT */
}

/* Returns true (non-zero) if the socket behind the stream has IP options set.
   This returns FALSE if the stream is not a socket stream. */

Boolean ssh_tcp_low_has_ip_options(SshStream stream)
{
  SshIOHandle sock;
  int ret = -1;
  char *options;
#ifndef VXWORKS
  ssh_socklen_t option_size;
#else
  int option_size;
#endif

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;
  option_size = 8192;
  if ((options = ssh_malloc(option_size)) != NULL)
    {
      ret = getsockopt(sock, IPPROTO_IP, IP_OPTIONS, options,
                       &option_size);
      ssh_free(options);
    }
  else
    option_size = 0;

  return (ret >= 0 && option_size != 0);
}

/* Returns the local and remove ip and port numbers. Any of the fields can be
   NULL, in which case it is not filled. Returns FALSE if the stream is not a
   socket stream. */
Boolean ssh_tcp_low_get_ip_addresses(SshStream stream,
                                     SshIpAddr local_ip,
                                     SshUInt16 *local_port,
                                     SshIpAddr remote_ip,
                                     SshUInt16 *remote_port)
{
  SshIOHandle sock;
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

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  if (remote_ip || remote_port)
    {
      saddrlen = sizeof(saddr);
      if (getpeername(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
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
      if (getsockname(sock, (struct sockaddr *)&saddr, &saddrlen) < 0)
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

/* Sets/resets TCP options TCP_NODELAY for the socket.  */

Boolean ssh_tcp_low_set_nodelay(SshStream stream, Boolean on)
{
#ifdef ENABLE_TCP_NODELAY
  int onoff = on;
  SshIOHandle sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&onoff,
                    (ssh_socklen_t) sizeof(onoff)) == 0;
#else /* ENABLE_TCP_NODELAY */
  return FALSE;
#endif /* ENABLE_TCP_NODELAY */
}

/* Sets/resets socket options SO_KEEPALIVE for the socket.  */

Boolean ssh_tcp_low_set_keepalive(SshStream stream, Boolean on)
{
  int onoff = on;
  SshIOHandle sock;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

#if defined (SOL_SOCKET) && defined (SO_KEEPALIVE)
  return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&onoff,
                    (ssh_socklen_t) sizeof(onoff)) == 0;
#else /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
  return FALSE;
#endif /* defined (SOL_SOCKET) && defined (SO_KEEPALIVE) */
}

/* Sets/resets socket options SO_LINGER for the socket.  */

Boolean ssh_tcp_low_set_linger(SshStream stream, Boolean on)
{
#if defined (SOL_SOCKET) && defined (SO_LINGER)
  SshIOHandle sock;
  struct linger linger;

  linger.l_onoff = on ? 1 : 0;
  linger.l_linger = on ? 15 : 0;

  sock = ssh_stream_fd_get_readfd(stream);
  if (sock == -1)
    return FALSE;

  return setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger,
                    (ssh_socklen_t) sizeof(linger)) == 0;
#else /* defined (SOL_SOCKET) && defined (SO_LINGER) */
  return FALSE;
#endif /* defined (SOL_SOCKET) && defined (SO_LINGER) */
}

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

/* --------- function for listening for connections ---------- */

typedef struct SshTcpPlatformListenerRec
SshTcpPlatformListenerStruct, *SshTcpPlatformListener;

struct SshTcpPlatformListenerRec
{
  SshIOHandle sock;
  char *path;
  SshTcpCallback callback;
  void *context;
  SshTcpPlatformListener sibling;
};

/* This callback is called whenever a new connection is made to a listener
   socket. */

void ssh_tcp_listen_callback(unsigned int events, void *context)
{
  SshTcpPlatformListener listener = (SshTcpPlatformListener) context;
  SshIOHandle sock;
#ifdef HAVE_SOCKADDR_IN6_STRUCT
  struct sockaddr_in6 sinaddr;
#else
  struct sockaddr_in sinaddr;
#endif
#ifndef VXWORKS
  ssh_socklen_t addrlen;
#else
  int addrlen;
#endif

  if (events & SSH_IO_READ)
    {
      SshStream stream;

      addrlen = sizeof(sinaddr);
      sock = accept(listener->sock, (struct sockaddr *)&sinaddr, &addrlen);
      if (sock < 0)
        {
          ssh_debug("ssh_tcp_listen_callback: accept failed");
          return;
        }

      /* Re-enable requests on the listener. */
      ssh_io_set_fd_request(listener->sock, SSH_IO_READ);

      if ((stream = ssh_stream_fd_wrap(sock, TRUE)) == NULL)
        {
          close(sock);
          return;
        }

      ssh_stream_set_private_methods(stream,
                              (void *) ssh_tcp_connect_platform_methods(NULL));

      ssh_stream_fd_mark_forked(stream);

      /* Inform user callback of the new socket.  Note that this might
         destroy the listener. */
      (*listener->callback)(SSH_TCP_NEW_CONNECTION,
                            stream,
                            listener->context);
    }
}

/* Creates a socket that listens for new connection. */
static SshTcpPlatformListener
ssh_tcp_make_listener_one_ip(SshIpAddr local_address,
                             SshUInt16 local_port,
                             int interface_index,
                             int routing_instance_id,
                             const SshTcpListenerParams params,
                             SshTcpCallback callback,
                             void *context)
{
  SshIOHandle sock = -1;
  int listen_backlog, buf_len;
  SshTcpPlatformListener listener;

  /* Create a socket. */
  sock = ssh_tcp_create_socket(local_address);
  if (sock < 0)
    return NULL;

  if (!params)
    {
      ssh_socket_set_reuseaddr(sock);
    }
  else
    {
      switch (params->listener_reusable)
        {
        case SSH_TCP_REUSABLE_PORT:
          ssh_socket_set_reuseport(sock);
          break;
        case SSH_TCP_REUSABLE_ADDRESS:
          ssh_socket_set_reuseaddr(sock);
          break;
        case SSH_TCP_REUSABLE_BOTH:
          ssh_socket_set_reuseport(sock);
          ssh_socket_set_reuseaddr(sock);
          break;
        case SSH_TCP_REUSABLE_NONE:
          break;
        }
    }

  if (SSH_IP_IS6(local_address))
    {
#ifdef HAVE_SOCKADDR_IN6_STRUCT
      struct sockaddr_in6 sinaddr6;

      memset(&sinaddr6, 0, sizeof(sinaddr6));
      sinaddr6.sin6_family = AF_INET6;
      sinaddr6.sin6_port = htons(local_port);
      memcpy(sinaddr6.sin6_addr.s6_addr, local_address->addr_data, 16);

      if (bind(sock, (struct sockaddr *)&sinaddr6,
               (ssh_socklen_t) sizeof(sinaddr6)) < 0)
        {
          goto error_local;
        }
#endif /* HAVE_SOCKADDR_IN6_STRUCT */
    }
  else if (SSH_IP_IS4(local_address))
    {
      struct sockaddr_in sinaddr;

      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;
      sinaddr.sin_port = htons(local_port);
      sinaddr.sin_addr.s_addr = htonl(SSH_IP4_TO_INT(local_address));

      if (bind(sock, (struct sockaddr *)&sinaddr,
               (ssh_socklen_t) sizeof(sinaddr)) < 0)
        {
          goto error_local;
        }
    }

  listen_backlog = 16;
  if (params && params->listen_backlog != 0)
    listen_backlog = params->listen_backlog;
  if (listen(sock, listen_backlog) < 0)
    {
      goto error_local;
    }

#ifdef SO_SNDBUF
  if (params && params->send_buffer_size != 0)
    {
      buf_len = params->send_buffer_size;
      if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&buf_len,
                     (ssh_socklen_t) sizeof(int)) == -1)
        {
          SSH_DEBUG(3,
                    ("ssh_tcp_make_listener_one_ip: setsockopt "
                     "SO_SNDBUF failed: %s",
                     strerror(errno)));
        }
    }
#endif /* SO_SNDBUF */
#ifdef SO_RCVBUF
  if (params && params->receive_buffer_size != 0)
    {
      buf_len = params->receive_buffer_size;
      if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&buf_len,
                     (ssh_socklen_t) sizeof(int)) == -1)
        {
          SSH_DEBUG(3,
                    ("ssh_tcp_make_listener_one_ip: setsockopt "
                     "SO_RCVBUF failed: %s",
                     strerror(errno)));
        }
    }
#endif /* SO_RCVBUF */

  if ((listener = ssh_calloc(1, sizeof(*listener))) != NULL)
    {
      listener->sock = sock;
      listener->path = NULL;
      listener->callback = callback;
  listener->context = context;

  if (ssh_io_register_fd(sock, ssh_tcp_listen_callback, (void *)listener)
          == FALSE)
        {
          ssh_free(listener);
          goto error_local;
        }
      ssh_io_set_fd_request(sock, SSH_IO_READ);
      return listener;
    }

 error_local:
  ssh_tcp_close_socket(sock);
  return NULL;
}

/* Creates a socket that listens for new connections.  The address
   must be an ip-address in the form "nnn.nnn.nnn.nnn".  "0.0.0.0"
   indicates any host; otherwise it should be the address of some
   interface on the system.  The given callback will be called whenever
   a new connection is received at the socket.  This returns NULL on error. */

static SshTcpPlatformListener
ssh_tcp_make_ip4_listener(const unsigned char *local_address,
                          const unsigned char *port_or_service,
                          int interface_index,
                          int routing_instance_id,
                          const SshTcpListenerParams params,
                          SshTcpCallback callback,
                          void *context)
{
  SshIpAddrStruct ipaddr[1];
  int port;

  if (!local_address || SSH_IS_IPADDR_ANY(local_address))
    local_address = ssh_custr(SSH_IP4_NULLADDR);

  if (!ssh_ipaddr_parse(ipaddr, local_address))
    return NULL;

  /* Parse port and address. */
  port = ssh_inet_get_port_by_service(port_or_service, ssh_custr("tcp"));

  return ssh_tcp_make_listener_one_ip(ipaddr, port,
                                      interface_index,
                                      routing_instance_id,
                                      params, callback, context);
}

#ifdef SSH_HAVE_IPV6
/* Creates a socket that listens for new connections.  The address
   must be an ip-address in the form "nnn.nnn.nnn.nnn".  "0.0.0.0"
   indicates any host; otherwise it should be the address of some
   interface on the system.  The given callback will be called whenever
   a new connection is received at the socket.  This returns NULL on error. */

static SshTcpPlatformListener
ssh_tcp_make_ip6_listener(const unsigned char *local_address,
                          const unsigned char *port_or_service,
                          int interface_index,
                          int routing_instance_id,
                          const SshTcpListenerParams params,
                          SshTcpCallback callback,
                          void *context)
{
  SshIpAddrStruct ipaddr[1];
  int port;

  if (!local_address || SSH_IS_IPADDR_ANY(local_address))
    local_address = ssh_custr(SSH_IP6_NULLADDR);

  if (!ssh_ipaddr_parse(ipaddr, local_address))
    return NULL;

  /* Parse port and address. */
  port = ssh_inet_get_port_by_service(port_or_service, ssh_custr("tcp"));

  return ssh_tcp_make_listener_one_ip(ipaddr, port,
                                      interface_index,
                                      routing_instance_id,
                                      params, callback, context);
}
#endif /* SSH_HAVE_IPV6 */

/* Creates a socket that listens for new connection. */
void *
ssh_tcp_low_make_listener_ip(void *listener_method_context,
                             SshIpAddr local_address,
                             SshUInt16 local_port,
                             int interface_index,
                             int routing_instance_id,
                             const SshTcpListenerParams params,
                             SshTcpCallback callback,
                             void *context)
{
  SshTcpPlatformListener listener4 = NULL;
#ifdef SSH_HAVE_IPV6
  SshTcpPlatformListener listener6 = NULL;
#endif /* SSH_HAVE_IPV6 */
  SshIpAddrStruct ip[1];

  memset(&ip, 0, sizeof(ip));

  SSH_DEBUG(SSH_D_HIGHSTART, ("Making TCP listener"));

  if (local_address != NULL)
    {
      return ssh_tcp_make_listener_one_ip(local_address, local_port,
                                          interface_index,
                                          routing_instance_id,
                                          params, callback, context);
    }
  /* Create a dual listener for both IPv4 and IPv6. */
  SSH_DEBUG(SSH_D_HIGHSTART, ("Making IPv4 and IPv6 TCP listeners"));

#ifdef SSH_HAVE_IPV6
  /* Try to create an IPv6 listener.  It is ok if this fails since
     there seems to be systems which do not support IPv6 although they
     know the in6 structures. */
  ssh_ipaddr_parse(ip, (unsigned char *)"::");
  listener6 = ssh_tcp_make_listener_one_ip(ip, local_port,
                                           interface_index,
                                           routing_instance_id,
                                           params, callback, context);
#endif /* SSH_HAVE_IPV6 */
  ssh_ipaddr_parse(ip, (unsigned char *)"0.0.0.0");
  listener4 = ssh_tcp_make_listener_one_ip(ip, local_port,
                                           interface_index,
                                           routing_instance_id,
                                           params, callback, context);
#ifdef SSH_HAVE_IPV6
  if ((listener4 != NULL) && (listener6 != NULL))
    listener4->sibling = listener6;
  else if (listener4 == NULL)
    listener4 = listener6;
#endif /* SSH_HAVE_IPV6 */
  return listener4;
}

void *
ssh_tcp_low_make_listener(void *listener_method_context,
                          const unsigned char *local_address,
                          const unsigned char *port_or_service,
                          int interface_index,
                          int routing_instance_id,
                          const SshTcpListenerParams params,
                          SshTcpCallback callback,
                          void *context)
{
  SshTcpPlatformListener listener4 = NULL;
#ifdef SSH_HAVE_IPV6
  SshTcpPlatformListener listener6 = NULL;
#endif /* SSH_HAVE_IPV6 */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Making TCP listener"));

  /* Let's determine the type of listener to create. */
  if (local_address && !SSH_IS_IPADDR_ANY(local_address))
    {
      SshIpAddrStruct ipaddr;

      /* We are creating only an IPv4 or an IPv6 listener. */
      if (!ssh_ipaddr_parse(&ipaddr, local_address))
        /* Malformed address. */
        return NULL;

      if (SSH_IP_IS4(&ipaddr))
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv4 only TCP listener for address %@",
                     ssh_ipaddr_render, &ipaddr));
          return ssh_tcp_make_ip4_listener(local_address, port_or_service,
                                           interface_index,
                                           routing_instance_id,
                                           params, callback, context);
        }
      else
        {
#ifdef SSH_HAVE_IPV6
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Making IPv6 only TCP listener for address %@",
                     ssh_ipaddr_render, &ipaddr));
          return ssh_tcp_make_ip6_listener(local_address, port_or_service,
                                           interface_index,
                                           routing_instance_id,
                                           params, callback, context);
#else /* not  SSH_HAVE_IPV6 */
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("IPv6 is not supported on this platform"));
          return NULL;
#endif /* not SSH_HAVE_IPV6 */
        }
    }

  /* Create a dual listener for both IPv4 and IPv6. */
  SSH_DEBUG(SSH_D_HIGHSTART, ("Making IPv4 and IPv6 TCP listeners"));

#ifdef SSH_HAVE_IPV6
  /* Try to create an IPv6 listener.  It is ok if this fails since
     there seems to be systems which do not support IPv6 although they
     know the in6 structures. */
  listener6 = ssh_tcp_make_ip6_listener(ssh_custr(SSH_IPADDR_ANY_IPV6),
                                        port_or_service,
                                        interface_index,
                                        routing_instance_id,
                                        params,
                                        callback,
                                        context);
#endif /* SSH_HAVE_IPV6 */
  listener4 = ssh_tcp_make_ip4_listener(ssh_custr(SSH_IPADDR_ANY_IPV4),
                                        port_or_service,
                                        interface_index,
                                        routing_instance_id,
                                        params,
                                        callback,
                                        context);
#ifdef SSH_HAVE_IPV6
  if ((listener4 != NULL) && (listener6 != NULL))
    listener4->sibling = listener6;
  else if (listener4 == NULL)
    listener4 = listener6;
#endif /* SSH_HAVE_IPV6 */
  return listener4;
}

/* Returns the local port used by the tcp listener. This can be used if local
   port in the make lister was zero or NULL, meaning any port.  */
SshUInt16
ssh_tcp_low_listener_get_local_port_number(void *listener_method_context,
                                           void *listener_context)
{
  SshTcpPlatformListener listener = listener_context;
  struct sockaddr_in addr;
#ifndef VXWORKS
  ssh_socklen_t addr_len = sizeof(addr);
#else
  int addr_len = (int)sizeof(addr);
#endif

  if (getsockname(listener->sock, (struct sockaddr *)&addr, &addr_len) < 0)
    return 0;
  return ntohs(addr.sin_port);
}

Boolean
ssh_tcp_low_listener_get_local_port(SshTcpPlatformListener listener,
                                    unsigned char *buf,
                                    size_t buflen)
{
  struct sockaddr_in addr;
#ifndef VXWORKS
  ssh_socklen_t addr_len = sizeof(addr);
#else
  int addr_len = (int)sizeof(addr);
#endif

  if (getsockname(listener->sock, (struct sockaddr *)&addr, &addr_len) < 0)
    return FALSE;



  return (ssh_snprintf(buf, buflen, "%u", ntohs(addr.sin_port)) > 0);
}

/* Destroys the socket.  It is safe to call this from a callback. */

void
ssh_tcp_low_destroy_listener(void *listener_method_context,
                             void *listener_context)
{
  SshTcpPlatformListener listener = listener_context;

  if (listener->sibling)
    ssh_tcp_low_destroy_listener(listener_method_context,
                                 listener->sibling);

  ssh_io_unregister_fd(listener->sock, FALSE);
  ssh_tcp_close_socket(listener->sock);

  if (listener->path)
    {
      /* Do not remove the listener here.  There are situations where we
         fork after creating a listener, and want to close it in one but not
         the other fork.  Thus, listeners should be removed by the application
         after they have been destroyed. */
      /* remove(listener->path); */
      ssh_free(listener->path);
    }
  ssh_free(listener);
}


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

/* -------------- functions for name server lookups ------------------ */

/* Gets the name of the host we are running on.  To get the corresponding IP
   address(es), a name server lookup must be done using the functions below. */

void ssh_tcp_get_host_name(unsigned char *buf, size_t buflen)
{
#if !defined(HAVE_GETHOSTNAME) && defined(HAVE_UNAME)
  struct utsname uts;
#endif

#ifdef HAVE_GETHOSTNAME
  if (gethostname(ssh_sstr(buf), buflen) < 0)
    {
      ssh_debug("gethostname failed, buflen %u, errno %d", buflen, errno);
      strncpy(ssh_sstr(buf), "UNKNOWN", buflen);
    }
#else /* HAVE_GETHOSTNAME */
# ifdef HAVE_UNAME
  if (uname(&uts) < 0)
    {
      ssh_debug("uname failed: %s", strerror(errno));
      strncpy(buf, "UNKNOWN", buflen);
    }
  else
    strncpy(buf, uts.nodename, buflen);
# else /* HAVE_UNAME */
  strncpy(buf, "UNKNOWN", buflen);
# endif /* HAVE_UNAME */
#endif /* HAVE_GETHOSTNAME */
}

/* Looks up all ip-addresses of the host, returning them as a
   comma-separated list. The host name may already be an ip address,
   in which case it is returned directly. This is an simplification
   of function ssh_tcp_get_host_addrs_by_name for situations when
   the operation may block.

   The function returns NULL if the name can not be resolved. When the
   return value is non null, it is a pointer to a string allocated by
   this function, and must be freed by the caller when no longer
   needed. */
unsigned char *ssh_tcp_get_host_addrs_by_name_sync(const unsigned char *name)
{
#ifdef VXWORKS
  struct in_addr address;
  unsigned char outbuf[INET_ADDR_LEN+1];
  size_t outbuflen = 4;
#else /* VXWORKS */
  unsigned char *addresses, *tmp;
  size_t addr_len, addr_ptr;
  unsigned char outbuf[16];
  struct hostent *hp;
  size_t outbuflen = 16;
  SshIpAddrStruct ip;
  int i;
# ifdef HAVE_GETIPNODEBYNAME
  int error_num;
# endif /* HAVE_GETIPNODEBYNAME */
#endif /* VXWORKS */

  /* First check if it is already an ip address. */
  if (ssh_inet_strtobin(name, outbuf, &outbuflen))
    return ssh_strdup(name);

#ifdef VXWORKS
  address.s_addr = hostGetByName((char *)name);
  if (address.s_addr == ERROR) return NULL;
  inet_ntoa_b(address, outbuf);
  return ssh_strdup(outbuf);
#else /* VXWORKS */

# ifdef HAVE_GETIPNODEBYNAME
  hp = getipnodebyname(ssh_csstr(name), AF_INET6,
                       AI_V4MAPPED | AI_ADDRCONFIG | AI_ALL,
                       &error_num);
  if (!hp)
    {
      /* This kludge needed for BSDI (getipnodebyname() returns NULL,
         if AF_INET6 and AI_ADDRCONFIG are specified in a system
         without IPv6 interfaces). */
      hp = getipnodebyname(ssh_csstr(name), AF_INET,
                           AI_V4MAPPED | AI_ADDRCONFIG | AI_ALL,
                           &error_num);
      if (!hp)
        return NULL;
    }

  if (!hp->h_addr_list[0])
    {
      freehostent(hp);
      return NULL;
    }
  outbuflen = 16;
# else /* HAVE_GETIPNODEBYNAME */
  /* Look up the host from the name servers. */
#  ifdef HAVE_GETHOSTBYNAME2
#   ifdef AF_INET6
  hp = gethostbyname2((char *)name, AF_INET6);
#   else /* AF_INET6 */
  hp = NULL;
#   endif /* AF_INET6 */

  outbuflen = 16;
#  else /* HAVE_GETHOSTBYNAME2 */
  hp = gethostbyname((char *)name);
  outbuflen = 4;
#  endif /* HAVE_GETHOSTBYNAME2 */
# endif /* HAVE_GETIPNODEBYNAME */


  /* Format the addresses into a comma-separated string. */
  addr_len = 64;
  if ((addresses = ssh_malloc(addr_len)) == NULL)
    {
# ifdef HAVE_GETIPNODEBYNAME
      freehostent(hp);
# endif /* HAVE_GETIPNODEBYNAME */
      return NULL;
    }

  addr_ptr = 0;
  addresses[addr_ptr] = '\0';
  if (hp && hp->h_addr_list[0])
    {
      for (i = 0; hp->h_addr_list[i]; i++)
        {
#ifndef HAVE_GETHOSTBYNAME2
          if (outbuflen == 4)
            {
              SSH_IP4_DECODE(&ip, hp->h_addr_list[i]);
            }
#ifdef WITH_IPV6
          else
#endif /* WITH_IPV6 */
#endif /* !HAVE_GETHOSTBYNAME2 */

#ifdef WITH_IPV6
            {
              SSH_IP6_DECODE(&ip, hp->h_addr_list[i]);

              /*
                There is no point in keeping v4-only addresses in
                v6 form. RFC1884, section 2.4.4.
              */
              ssh_inet_convert_ip6_mapped_ip4_to_ip4(&ip);

              /* Following is ugly.  It however seems to be so, that in
                 certain systems some IPv4 addresses may get erroneously
                 mapped to IPV6 addresses.  I hope that this is a
                 temporary kludge.  Also we shouldn't look into the
                 internals of the SshIpAddrStruct (sshinet.h). */
              if (SSH_IP_IS6(&ip) &&
                  (ip.mask_len == 128) &&
                  (ip.addr_data[4] == 0x0) &&
                  (ip.addr_data[5] == 0x0) &&
                  (ip.addr_data[6] == 0x0) &&
                  (ip.addr_data[7] == 0x0) &&
                  (ip.addr_data[8] == 0x0) &&
                  (ip.addr_data[9] == 0x0) &&
                  (ip.addr_data[10] == 0x0) &&
                  (ip.addr_data[11] == 0x0) &&
                  (ip.addr_data[12] == 0x0) &&
                  (ip.addr_data[13] == 0x0) &&
                  (ip.addr_data[14] == 0x0) &&
                  (ip.addr_data[15] == 0x0))
                continue;
            }
#endif /* WITH_IPV6 */

          if (addr_len - addr_ptr < 40)
            {
              if ((tmp = ssh_realloc(addresses, addr_len, 2 * addr_len))
                  != NULL)
                {
                  addresses = tmp;
                  addr_len *= 2;
                }
              else
                {
# ifdef HAVE_GETIPNODEBYNAME
                  freehostent(hp);
# endif /* HAVE_GETIPNODEBYNAME */
                  ssh_free(addresses);
                  return NULL;
                }
            }

          if (addr_ptr > 0)
            {
              addresses[addr_ptr++] = ',';
              addresses[addr_ptr] = '\0';
            }
          ssh_ipaddr_print(&ip, addresses + addr_ptr, addr_len - addr_ptr);
          addr_ptr += ssh_ustrlen(addresses + addr_ptr);
        }
    }

# ifdef HAVE_GETHOSTBYNAME2
  hp = gethostbyname2((char *)name, AF_INET);
  if (hp && hp->h_addr_list[0])
    {
      for (i = 0; hp->h_addr_list[i]; i++)
        {
          SSH_IP4_DECODE(&ip, hp->h_addr_list[i]);

          if (addr_len - addr_ptr < 40)
            {
              if ((tmp = ssh_realloc(addresses, addr_len, 2 * addr_len))
                  != NULL)
                {
                  addr_len *= 2;
                  addresses = tmp;
                }
              else
                {
                  ssh_free(addresses);
                  return NULL;
                }
            }

          if (addr_ptr > 0)
            {
              addresses[addr_ptr++] = ',';
              addresses[addr_ptr] = '\0';
            }
          ssh_ipaddr_print(&ip, addresses + addr_ptr, addr_len - addr_ptr);
          addr_ptr += strlen((char *)addresses + addr_ptr);
        }
    }
# endif /* HAVE_GETHOSTBYNAME2 */

  if (addresses[0])
    {
      return addresses;
    }
  else
    {
# ifdef HAVE_GETIPNODEBYNAME
      freehostent(hp);
# endif /* HAVE_GETIPNODEBYNAME */
      ssh_free(addresses);
      return NULL;
    }
#endif /* VXWORKS */
}

/* Looks up the name of the host by its ip-address.  Verifies that the
   address returned by the name servers also has the original ip
   address. This is an simplification of function
   ssh_tcp_get_host_by_addr for situations when the operation may
   block.

   Function returns NULL, if the reverse lookup fails for some reason,
   or pointer to dynamically allocated memory containing the host
   name.  The memory should be deallocated by the caller when no
   longer needed.  */

unsigned char *ssh_tcp_get_host_by_addr_sync(const unsigned char *addr)
{
#if defined (HAVE_GETIPNODEBYADDR) && defined (HAVE_GETIPNODEBYNAME)
  struct hostent *hp;
  unsigned char outbuf[16];
  size_t outbuflen = 16;
  int error_num;
  unsigned char *name;
  int i;

  if (!ssh_inet_strtobin(addr, outbuf, &outbuflen))
    return NULL;

  hp = getipnodebyaddr(outbuf, outbuflen,
                       (outbuflen == 16) ? AF_INET6 : AF_INET,
                       &error_num);
  if (!hp)
    return NULL;

  name = ssh_strdup(hp->h_name);
  freehostent(hp);

  if (name == NULL)
    return NULL;

  /* Map it back to an IP address and check that the given address
     actually is an address of this host.  This is necessary because
     anyone with access to a name server can define arbitrary names
     for an IP address.  Mapping from name to IP address can be
     trusted better (but can still be fooled if the intruder has
     access to the name server of the domain). */
  hp = getipnodebyname(ssh_csstr(name), (outbuflen == 16) ? AF_INET6 : AF_INET,
                       AI_V4MAPPED | AI_ADDRCONFIG | AI_ALL,
                       &error_num);
  if (!hp)
    {
      ssh_free(name);
      return NULL;
    }

  /* Look for the address from the list of addresses. */
  for (i = 0; hp->h_addr_list[i]; i++)
    if (memcmp(hp->h_addr_list[i], outbuf, outbuflen) == 0)
      break;
  /* If we reached the end of the list, the address was not there. */
  if (!hp->h_addr_list[i])
    {
      freehostent(hp);
      ssh_free(name);
      return NULL;
    }

  freehostent(hp);
  /* Address was found for the host name.  We accept the host name. */
  return name;
#else /* defined (HAVE_GETIPNODEBYADDR) && defined (HAVE_GETIPNODEBYNAME) */
#ifdef VXWORKS
  char name[MAXHOSTNAMELEN+1];
  size_t outbuflen = 4; /* IPv4 only in VxWorks */
  unsigned char outbuf[16];
  int address, address_2;

  if (!ssh_inet_strtobin(addr, outbuf, &outbuflen))
    return NULL;

  if (outbuflen!=4)
    return NULL; /* IPv4 only in VxWorks */

  memmove(&address, outbuf, outbuflen);
  if (hostGetByAddr(address, name) == ERROR) return NULL;

  /* Map it back to an IP address and check that the given address
     actually is an address of this host.  This is necessary because
     anyone with access to a name server can define arbitrary names
     for an IP address.  Mapping from name to IP address can be
     trusted better (but can still be fooled if the intruder has
     access to the name server of the domain). */
  address_2 = hostGetByName(name);
  if (address != address_2) return NULL;

  /* Address was found for the host name.  We accept the host name. */
  return (unsigned char *)ssh_strdup(name);

#else /* VXWORKS */
  unsigned char outbuf[16];
  size_t outbuflen = 16;
  struct hostent *hp;
  unsigned char *name;
  int i;

  if (!ssh_inet_strtobin(addr, outbuf, &outbuflen))
    return NULL;

#ifdef AF_INET6
  hp = gethostbyaddr((char *)outbuf, outbuflen,
                     (outbuflen == 16) ? AF_INET6 : AF_INET);
#else /* AF_INET6 */
  if (outbuflen == 16)
    return NULL;
  hp = gethostbyaddr((char *)outbuf, outbuflen, AF_INET);
#endif /* AF_INET6 */

  if (!hp)
    return NULL;

  /* Got host name. */
  if ((name = ssh_strdup(hp->h_name)) == NULL)
    return NULL;

  /* Map it back to an IP address and check that the given address
     actually is an address of this host.  This is necessary because
     anyone with access to a name server can define arbitrary names
     for an IP address.  Mapping from name to IP address can be
     trusted better (but can still be fooled if the intruder has
     access to the name server of the domain). */
  hp = gethostbyname((char *)name);
  if (!hp)
    {
      ssh_free(name);
      return NULL;
    }

  /* Look for the address from the list of addresses. */
  for (i = 0; hp->h_addr_list[i]; i++)
    if (hp->h_length == outbuflen &&
        memcmp(hp->h_addr_list[i], outbuf, outbuflen) == 0)
      break;
  /* If we reached the end of the list, the address was not there. */
  if (!hp->h_addr_list[i])
    {
      ssh_free(name);
      return NULL;
    }

  /* Address was found for the host name.  We accept the host name. */
  return name;
#endif /* VXWORKS */
#endif /* defined (HAVE_GETIPNODEBYADDR) && defined (HAVE_GETIPNODEBYNAME) */
}

/* Looks up the service (port number) by name and protocol.  `protocol' must
   be either "tcp" or "udp".  Returns -1 if the service could not be found. */

int ssh_inet_get_port_by_service(const unsigned char *name,
                                 const unsigned char *proto)
{
#ifdef HAVE_GETSERVBYNAME
  struct servent *se;
  int port;
#endif /* HAVE_GETSERVBYNAME */
  const unsigned char *cp;

  for (cp = name; isdigit(*cp); cp++)
    ;
  if (!*cp && *name)
    return ssh_uatoi(name);
#ifdef HAVE_GETSERVBYNAME
  se = getservbyname(ssh_csstr(name), ssh_csstr(proto));
  if (!se)
    return -1;
  port = ntohs(se->s_port);
#ifdef HAVE_ENDSERVENT
  endservent();
#endif /* HAVE_ENDSERVENT */
  return port;
#else  /* HAVE_GETSERVBYNAME */
#  ifdef WANT_SERVBYNAME
    {
      struct SshServent const *se;
      se = ssh_getserv(name, 0, TRUE, proto);
      return (se == NULL)? -1 : se->s_port;
    }
#  else /* WANT_SERVBYNAME */
  return -1;
#  endif /* WANT_SERVBYNAME */
#endif /* HAVE_GETSERVBYNAME */
}

/* Looks up the name of the service based on port number and protocol.
   `protocol' must be either "tcp" or "udp".  The name is stored in the
   given buffer; is the service is not found, the port number is stored
   instead (without the protocol specification).  The name will be
   truncated if it is too long. */

void ssh_inet_get_service_by_port(unsigned int port,
                                  const unsigned char *proto,
                                  unsigned char *buf, size_t buflen)
{
#ifdef HAVE_GETSERVBYPORT
  struct servent *se;

  se = getservbyport(htons(port), ssh_csstr(proto));
  if (!se)



    ssh_snprintf(buf, buflen, "%u", port);
  else
    strncpy(ssh_sstr(buf), se->s_name, buflen);
#ifdef HAVE_ENDSERVENT
  endservent();
#endif /* HAVE_ENDSERVENT */
#else /* HAVE_GETSERVBYPORT */
#  ifdef WANT_SERVBYPORT
    {
      struct SshServent const *se;
      se = ssh_getserv(NULL, port, FALSE, proto);
      if (se)
        if (se->s_aliases[0] != NULL)
          {
            strncpy(buf, se->s_aliases[0], buflen);
            return;
          }



      ssh_snprintf(ssh_sstr(buf), buflen, "%u", port);
    }
#  else /* WANT_SERVBY_PORT */



    ssh_snprintf(ssh_sstr(buf), buflen, "%u", port);
#  endif /* WANT_SERVBY_PORT */
#endif /* HAVE_GETSERVBYPORT */
}

/* --------------------- auxiliary functions -------------------------*/



/* Compares two port number addresses, and returns <0 if port1 is smaller,
   0 if they denote the same number (though possibly written differently),
   and >0 if port2 is smaller.  The result is zero if either address is
   invalid. */
int ssh_inet_port_number_compare(const unsigned char *port1,
                                 const unsigned char *port2,
                                 const unsigned char *proto)
{
  int nport1, nport2;

  nport1 = ssh_inet_get_port_by_service(port1, proto);
  nport2 = ssh_inet_get_port_by_service(port2, proto);

  if (nport1 == -1 || nport2 == -1)
    return 0;
  if (nport1 == nport2)
    return 0;
  else
    if (nport1 < nport2)
      return -1;
    else
      return 1;
}
