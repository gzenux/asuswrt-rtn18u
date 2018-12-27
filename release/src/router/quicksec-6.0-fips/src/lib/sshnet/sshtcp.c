/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to sockets.
*/

#include "sshincludes.h"
#include "sshstream.h"
#include "sshnameserver.h"
#include "sshtcp.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "sshsocks.h"
#include "sshurl.h"
#include "sshtimeouts.h"
#include "sshfsm.h"

#define SSH_DEBUG_MODULE "SshTcp"

static SshInetAccessRequestCallback *access_request_func;
static SshInetAccessReleaseCallback *access_release_func;
static void * access_param;

void
ssh_inet_access_callbacks_set(
        SshInetAccessRequestCallback *request_func,
        SshInetAccessReleaseCallback *release_func,
        void *param)
{
  access_request_func = request_func;
  access_release_func = release_func;
  access_param = param;
}


int
ssh_inet_make_access_request_callback(
        SshIpAddr local_address,
        SshIpAddr remote_address,
        int in_protocol,
        int local_port,
        int remote_port)
{
  if (access_request_func != NULL)
    {
      return
          access_request_func(
                  access_param,
                  local_address,
                  remote_address,
                  in_protocol,
                  local_port,
                  remote_port);
    }

  return -1;
}


void
ssh_inet_make_access_release_callback(
        int handle,
        int delay_seconds)
{
  if (access_release_func != NULL && handle != -1)
    {
      access_release_func(access_param, handle, delay_seconds);
    }
}


static SshTcpSocketRequestCallback *socket_request_func;
static SshTcpSocketReleaseCallback *socket_release_func;
static void * socket_param;

void
ssh_tcp_socket_callbacks_set(
        SshTcpSocketRequestCallback *request_func,
        SshTcpSocketReleaseCallback *release_func,
        void *param)
{
  socket_request_func = request_func;
  socket_release_func = release_func;
  socket_param = param;
}


int
ssh_tcp_make_socket_request_callback(
        Boolean ip6)
{
  if (socket_request_func != NULL)
    {
      return socket_request_func(socket_param, ip6);
    }

  return -1;
}


int
ssh_tcp_make_socket_release_callback(
        int sock)
{
  if (socket_release_func != NULL)
    {
      return socket_release_func(socket_param, sock);
    }

  return -1;
}


/* A context used to track SOCKS server connection status. */

typedef struct {
  /* Information about local binding. */
  unsigned char *local_address;
  unsigned int local_port;
  SshTcpReusableType local_reusable;

  /* Information about the target host. */
  unsigned char *host_name;             /* host to connect to. */
  unsigned char *host_addresses;        /* addresses for the host to connect */
  const unsigned char *next_address;    /* next address to try */
  unsigned int host_port;               /* port to connect on the host */
  SshUInt32 protocol_mask;              /* protocols used in connect */

  /* User callback. */
  SshTcpCallback user_callback;
  void *user_context;

  /* Miscellaneous request information. */
  unsigned int connection_attempts;
  unsigned int attempts_done;

  /* Information about the socks server. */
  unsigned char *socks_host;            /* socks server host */
  unsigned char *socks_exceptions;      /* exceptions when to use socks */
  unsigned char *socks_addresses;       /* socks server addresses */
  unsigned char *socks_next_address;    /* next address to try */
  unsigned int socks_port;              /* socks port */
  unsigned char *user_name;             /* user requesting connection */
  SshBuffer socks_buf;                  /* Socks buffer */
  SshTcpSocksType socks_type;           /* Socks type */
  /* An open stream to either the socks server or the final destination. */
  SshStream stream;

  /* Lower level operation handle. If this is set we are in the middle of the
     asyncronous call */
  SshOperationHandle handle;

  /* Platform dependent low level connect method and method context. */
  SshTcpConnectMethodsStruct methods;
  void *methods_context;
  SshTcpConnectParamsStruct params;

  /* Interface index and routing instance id. */
  int interface_index;
  int routing_instance_id;

  /* Upper level operation handle. If this is set we started any asyncronous
     call, and the lower level must free this structure. If this is NULL then
     we are in the syncronous code path and the ssh_tcp_connect will take care
     of the freeing of this structure */
  SshOperationHandle upper_handle;

  SshFSMStepCB next_state;
  SshTcpError error;
  SshFSM fsm;
  SshFSMThread thread;
  SshTimeoutStruct timeout;
} *ConnectContext;

SSH_FSM_STEP(tcp_connect_start);
SSH_FSM_STEP(tcp_connect_host_lookup);
SSH_FSM_STEP(tcp_connect_host_connect);
SSH_FSM_STEP(tcp_connect_socks_lookup);
SSH_FSM_STEP(tcp_connect_socks_connect);
SSH_FSM_STEP(tcp_connect_socks_send);
SSH_FSM_STEP(tcp_connect_socks_receive_read_byte);
SSH_FSM_STEP(tcp_connect_socks_receive_method);
SSH_FSM_STEP(tcp_connect_socks_receive);
SSH_FSM_STEP(tcp_connect_socks_error);
SSH_FSM_STEP(tcp_connect_socks_receive_method);
SSH_FSM_STEP(tcp_connect_finish);
SSH_FSM_STEP(tcp_connect_abort);
SSH_FSM_STEP(tcp_connect_cleanup);

/* Platforn dependent TCP connect implementation. This function is
   defined in the machine-specific file. */
SshTcpConnectMethods
ssh_tcp_connect_platform_methods(void **constructor_context_return);

/* Platforn dependent TCP listener implementation. This function is
   defined in the machine-specific file. */
SshTcpListenerMethods
ssh_tcp_listener_platform_methods(void **constructor_context_return);

/* Destroys the connection context. */
void tcp_connect_destroy_ctx(ConnectContext c);

/* Remove addresses that don't match the protocol match from the
   address list.  Overwrites the original list.  Can also return an
   empty string. */
void ssh_remove_non_matching_addresses_from_list(unsigned char *address,
                                                 SshUInt32 protocol_mask);

/* Return TRUE, if address os of type that is specified in the
   protocol mask. */
Boolean ssh_address_type_matches_protocol_mask(unsigned char *address,
                                               SshUInt32 protocol_mask);

/* Connection timed out */
void tcp_connect_time_out(void *context)
{
  ConnectContext c = context;

  c->error = SSH_TCP_TIMEOUT;
  ssh_fsm_set_next(c->thread, tcp_connect_finish);
  ssh_fsm_continue(c->thread);
}

/* Connection aborted out */
void ssh_tcp_connect_aborted(void *context)
{
  ConnectContext c = (ConnectContext) context;

  if (c->handle)
    {
      ssh_operation_abort(c->handle);
      c->handle = NULL;
    }
  /* Make sure we don't receive timeouts or call the user callback after
     we have been aborted. */
  c->user_callback = NULL_FNPTR;
  ssh_cancel_timeouts(tcp_connect_time_out, c);
  ssh_fsm_set_next(c->thread, tcp_connect_abort);
  ssh_fsm_continue(c->thread);
}

/* Opens a connection to the specified host, and calls the callback
   when the connection has been established or has failed.  If
   connecting is successful, the callback will be called with error
   set to SSH_TCP_OK and an SshStream object for the connection passed
   in in the stream argument.  Otherwise, error will indicate the
   reason for the connection failing, and the stream will be NULL.

   Note that the callback may be called either during this
   call or some time later.

   Returns SshOperationHandle that can be used to abort the tcp open.

   The `host_name_or_address' argument may be a numeric IP address or a
   host name (domain name), in which case it is looked up from the name
   servers.

   The params structure can either be NULL or memset to zero to get default
   parameters. All data inside the params is copied during this call, so it can
   be freed immediately when this function returns. */
SshOperationHandle ssh_tcp_connect(const unsigned char *host_name_or_address,
                                   const unsigned char *port_or_service,
                                   int interface_index,
                                   int routing_instance_id,
                                   const SshTcpConnectParams params,
                                   SshTcpCallback callback,
                                   void *context)
{
  ConnectContext c;

  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    {
      SSH_DEBUG(1, ("Failed to allocate TCP connection context."));
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  if (params && params->local_address)
    {
      c->local_address = ssh_strdup(params->local_address);
      if (c->local_address == NULL)
        {
        error_local:
          (*callback)(SSH_TCP_FAILURE, NULL, context);
          tcp_connect_destroy_ctx(c);
          return NULL;
        }

      if (params->local_port_or_service)
        {
          c->local_port
            = ssh_inet_get_port_by_service(params->local_port_or_service,
                                           ssh_custr("tcp"));
          if (c->local_port == 0)
            goto error_local;
        }
      c->local_reusable = params->local_reusable;
    }

  c->host_name = ssh_strdup(host_name_or_address);
  c->host_port = ssh_inet_get_port_by_service(port_or_service,
                                              ssh_custr("tcp"));
  c->host_addresses = NULL;
  c->next_address = NULL;

  if (c->host_name == NULL || c->host_port == 0)
    {
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      tcp_connect_destroy_ctx(c);
      return NULL;
    }

  if (params && (params->protocol_mask != 0))
    c->protocol_mask = params->protocol_mask;
  else
    c->protocol_mask = (~0);

  if (params && params->tcp_connect_methods)
    {
      c->methods = *params->tcp_connect_methods;
      c->methods_context = params->tcp_connect_methods_context;
      c->params = *params;
    }
  else
    {
      c->methods = *ssh_tcp_connect_platform_methods(&c->methods_context);
    }
  c->params.tcp_connect_methods = &c->methods;
  if (c->methods.connect_str == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP connect methods"));
      goto error_local;
    }

  c->interface_index = interface_index;
  c->routing_instance_id = routing_instance_id;

  c->user_callback = callback;
  c->user_context = context;
  if (params && params->connection_timeout != 0)
    {
      ssh_register_timeout(&c->timeout,
                           params->connection_timeout, 0,
                           tcp_connect_time_out, c);
    }

  c->connection_attempts = 1;
  if (params && params->connection_attempts != 0)
    c->connection_attempts = params->connection_attempts;

  c->attempts_done = 0;

  c->stream = NULL;

  /* Initialize socks-related data. */
  if (params &&
      params->socks_server_url != NULL &&
      ssh_usstrcmp(params->socks_server_url, "") != 0)
    {
      unsigned char *scheme, *port;

      if (ssh_url_parse_and_decode_relaxed(params->socks_server_url, &scheme,
                                           &(c->socks_host), &port,
                                           &(c->user_name), NULL,
                                           &(c->socks_exceptions)))
        {
          if (scheme != NULL && ssh_usstrcmp(scheme, "socks") != 0)
            ssh_warning("Socks server scheme not socks");
          if (scheme != NULL)
            ssh_free(scheme);

          if (c->socks_host != NULL)
            {
              if ((c->socks_buf = ssh_buffer_allocate()) == NULL)
                {
                  (*callback)(SSH_TCP_FAILURE, NULL, context);
                  tcp_connect_destroy_ctx(c);
                  return NULL;
                }
              c->socks_addresses = NULL;
              if (port == NULL || ssh_usstrcmp(port, "") == 0)
                c->socks_port = 1080; /* The standard socks port. */
              else
                c->socks_port = ssh_inet_get_port_by_service(port,
                                                             ssh_custr("tcp"));
            }
          if (port != NULL)
            ssh_free(port);
        }
      else
        {
          ssh_warning("Socks server URL is malformed.");
        }
    }
  else
    c->socks_host = NULL;

  if (params)
    c->socks_type = params->socks_type;

  c->upper_handle = NULL;
  c->handle = NULL;

  c->fsm = ssh_fsm_create(c);
  if (c->fsm == NULL)
    {
      SSH_DEBUG(2, ("Creating FSM failed."));
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      tcp_connect_destroy_ctx(c);
      return NULL;
    }
  c->thread = ssh_fsm_thread_create(c->fsm, tcp_connect_start,
                                    NULL_FNPTR, NULL_FNPTR, NULL);
  if (c->thread == NULL)
    {
      SSH_DEBUG(2, ("Creating thread failed."));
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      ssh_fsm_destroy(c->fsm);
      tcp_connect_destroy_ctx(c);
      return NULL;
    }
  c->upper_handle = ssh_operation_register(ssh_tcp_connect_aborted, c);
  return c->upper_handle;
}


SshOperationHandle ssh_tcp_connect_str(const unsigned char *local_address,
                                       unsigned int local_port,
                                       SshTcpReusableType local_reusable,
                                       const unsigned char *address_list,
                                       unsigned int port,
                                       int interface_index,
                                       int routing_instance_id,
                                       const SshTcpConnectParams params,
                                       SshTcpCallback callback,
                                       void *context)
{
  SshTcpConnectMethodsStruct methods;
  void *methods_context;

  if (params && params->tcp_connect_methods)
    {
      methods = *params->tcp_connect_methods;
      methods_context = params->tcp_connect_methods_context;
    }
  else
    {
      methods = *ssh_tcp_connect_platform_methods(&methods_context);
    }

  if (methods.connect_str == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP connect methods"));
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  return (*methods.connect_str)(methods_context,
                                local_address,
                                local_port,
                                local_reusable,
                                address_list,
                                port,
                                interface_index,
                                routing_instance_id,
                                params,
                                callback,
                                context);
}


SshOperationHandle
ssh_tcp_connect_ip(SshIpAddr remote_address,
                   SshUInt16 remote_port,
                   SshIpAddr local_address,
                   SshUInt16 local_port,
                   int interface_index,
                   int routing_instance_id,
                   const SshTcpConnectParams params,
                   SshTcpCallback callback,
                   void *context)
{
  SshTcpConnectMethodsStruct methods;
  void *methods_context;

  if (params && params->tcp_connect_methods)
    {
      methods = *params->tcp_connect_methods;
      methods_context = params->tcp_connect_methods_context;
    }
  else
    {
      methods = *ssh_tcp_connect_platform_methods(&methods_context);
    }

  if (methods.connect_ip == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP connect methods"));
      (*callback)(SSH_TCP_FAILURE, NULL, context);
      return NULL;
    }

  return (*methods.connect_ip)(methods_context,
                               remote_address,
                               remote_port,
                               local_address,
                               local_port,
                               interface_index,
                               routing_instance_id,
                               params,
                               callback,
                               context);
}

/* Destroys the connection context. */
void tcp_connect_destroy_ctx(ConnectContext c)
{
  SSH_DEBUG(4, ("Destroying ConnectContext..."));
  SSH_PRECOND(c != NULL);
  if (c->handle)
    ssh_operation_abort(c->handle);

  ssh_cancel_timeout(&c->timeout);
  ssh_free(c->local_address);
  ssh_free(c->host_name);
  ssh_free(c->host_addresses);
  ssh_free(c->socks_host);
  ssh_free(c->socks_addresses);
  ssh_free(c->user_name);
  ssh_free(c->socks_exceptions);
  if (c->socks_buf)
    ssh_buffer_free(c->socks_buf);
  if (c->stream)
    ssh_stream_destroy(c->stream);
  if (c->upper_handle)
    ssh_operation_unregister(c->upper_handle);

  ssh_free(c);
}

Boolean tcp_connect_register_failure(SshFSMThread thread, SshTcpError error)
{
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);

  c->attempts_done++;
  if (c->attempts_done < c->connection_attempts)
    return FALSE;

  c->error = error;
  ssh_fsm_set_next(thread, tcp_connect_finish);
  return TRUE;
}

SSH_FSM_STEP(tcp_connect_start)
{
  SSH_FSM_SET_NEXT(tcp_connect_host_lookup);
  return SSH_FSM_CONTINUE;
}

/* This callback is called when the host addresses have been looked up. */
void tcp_connect_host_lookup_cb(SshTcpError error,
                                const unsigned char *result,
                                void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);
  unsigned char *addrs = NULL;

  SSH_DEBUG(10, ("Got error %d, result = `%s'.", error,
                 result ? result : ssh_custr("NULL")));
  c->handle = NULL;
  if (error == SSH_TCP_OK)
    {
      if ((addrs = ssh_strdup(result)) == NULL)
        {
          error = SSH_TCP_FAILURE;
        }
      else
        {
          ssh_remove_non_matching_addresses_from_list(addrs, c->protocol_mask);
          if (ssh_ustrlen(addrs) == 0)
            {
              ssh_free(addrs);
              addrs = NULL;
              error = SSH_TCP_NO_ADDRESS;
            }
        }
    }
  if (error != SSH_TCP_OK)
    {
      if (c->socks_type == SSH_TCP_SOCKS5 && c->socks_host)
        {
          SSH_DEBUG(2, ("Couldn't resolve client address, trying to connect "
                        "with SOCKS5 server."));
          SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
          return;
        }
      SSH_FSM_SET_NEXT(tcp_connect_host_lookup);
      tcp_connect_register_failure(thread, error);
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  c->host_addresses = addrs;
  c->next_address = c->host_addresses;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(tcp_connect_host_lookup)
{
  ConnectContext c = (ConnectContext) fsm_context;

  if (c->socks_host)
    SSH_FSM_SET_NEXT(tcp_connect_socks_lookup);
  else
    SSH_FSM_SET_NEXT(tcp_connect_host_connect);

  SSH_DEBUG(10, ("Starting address lookup for host `%s'.", c->host_name));

  SSH_FSM_ASYNC_CALL(c->handle = ssh_tcp_get_host_addrs_by_name
                     (c->host_name, tcp_connect_host_lookup_cb,
                      thread));
}

void tcp_connect_socks_lookup_cb(SshTcpError error,
                                 const unsigned char *result, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);

  c->handle = NULL;
  if (error != SSH_TCP_OK)
    {
      SSH_DEBUG(0, ("Couldn't resolve IP for SOCKS server `%s'.",
                    c->socks_host));
      tcp_connect_register_failure(thread, error);
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  /* Save the lookup result. */
  if ((c->socks_addresses = ssh_strdup(result)) == NULL)
    {
      if (tcp_connect_register_failure(thread, error))
        {
          SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
          return;
        }
    }

  ssh_free(c->socks_next_address);
  c->socks_next_address = c->socks_addresses;




  /* Enter the next state. */
  if (c->socks_exceptions &&
      /* If we are trying SOCKS5, and host address couldn't be resolved,
         don't try to match with exceptions. */
      !((c->socks_type == SSH_TCP_SOCKS5) && !c->next_address))
    {
      unsigned char *next;
      SshIpAddrStruct ipaddr;

      next = ssh_ustrchr(c->next_address, ',');
      if (next)
        *next = '\0';

      if (! ssh_ipaddr_parse(&ipaddr, c->next_address))
        SSH_FSM_SET_NEXT(tcp_connect_host_connect);
      /* SOCKS5 can handle IPv6. */
      else if (SSH_IP_IS6(&ipaddr) && c->socks_type == SSH_TCP_SOCKS4)
        SSH_FSM_SET_NEXT(tcp_connect_host_connect);
      else if (ssh_inet_compare_netmask(c->socks_exceptions,
                                        c->next_address))
        SSH_FSM_SET_NEXT(tcp_connect_host_connect);
      else
        SSH_FSM_SET_NEXT(tcp_connect_socks_connect);

      if (next)
        *next = ',';
    }
  else
    {
      SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(tcp_connect_socks_lookup)
{
  ConnectContext c = (ConnectContext) fsm_context;

  SSH_DEBUG(5, ("Resolving SOCKS server `%s' IP.", c->socks_host));
  SSH_FSM_ASYNC_CALL(c->handle = ssh_tcp_get_host_addrs_by_name
                     (c->socks_host, tcp_connect_socks_lookup_cb, thread));
}

/* We are called whenever a notification is received from the stream.
   This shouldn't really happen unless read/write has failed, though
   I wouldn't count on it.  */

void tcp_connect_socks_notify(SshStreamNotification notification,
                              void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);

  c->handle = NULL;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
    case SSH_STREAM_CAN_OUTPUT:
      /* Just retry the processing for the current state. */
      break;

    case SSH_STREAM_DISCONNECTED:
      SSH_DEBUG(1, ("ssh_socket_socks_notify: DISCONNECTED"));
      ssh_stream_destroy(c->stream);
      c->stream = NULL;
      /* Count this as a failure. */
      if (tcp_connect_register_failure(thread, SSH_TCP_FAILURE))
        break;
      if (c->socks_host)
        {
          if (c->socks_type == SSH_TCP_SOCKS5 &&
              !c->host_addresses)
            {
              SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
            }
          else if (c->socks_exceptions)
            {
              unsigned char *next;
              next = ssh_ustrchr(c->host_addresses, ',');
              if (next)
                *next = '\0';
              if (ssh_inet_compare_netmask(c->socks_exceptions,
                                           c->host_addresses))
                SSH_FSM_SET_NEXT(tcp_connect_host_connect);
              else
                SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
              if (next)
                *next = ',';
            }
          else
            {
              SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
            }
        }
      else
        {
          SSH_FSM_SET_NEXT(tcp_connect_host_connect);
        }
      break;

    default:
      ssh_fatal("ssh_socket_socks_notify: unexpected notification %d",
                (int)notification);
    }
  ssh_fsm_continue(thread);
}

void tcp_connect_socks_connect_done_cb(SshTcpError error,
                                       SshStream stream,
                                       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);
  struct SocksInfoRec socksinfo;
  SocksError ret = SSH_SOCKS_SUCCESS;
  unsigned char host_port[64], *next = NULL;

  c->handle = NULL;

  if (error != SSH_TCP_OK)
    {
      /* Get next address. */
      if (ssh_ustrchr(c->socks_next_address, ','))
        {
          c->socks_next_address =
            ssh_ustrchr(c->socks_next_address, ',') + 1;
        }
      else
        { /* At end of list; consider it as a failure. */
          if (tcp_connect_register_failure(thread, error))
            {
              SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
              return;
            }
          c->socks_next_address = c->socks_addresses;
        }
      /* Try connecting again. */
      SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  /* Save the stream. */
  c->stream = stream;

  /* Set the callback so that we'll get any required read/write
     notifications. */
  ssh_stream_set_callback(stream, tcp_connect_socks_notify, thread);

  if (c->next_address &&
      (next = ssh_ustrchr(c->next_address, ',')) != NULL)
    {
      *next = '\0';
      next++;
    }

  if (c->socks_type == SSH_TCP_SOCKS5)
    {
      socksinfo.socks_version_number = 5;
      socksinfo.command_code = SSH_SOCKS5_COMMAND_CODE_CONNECT;
      if (c->next_address)
        socksinfo.ip = (unsigned char *) c->next_address;
      else
        socksinfo.ip = c->host_name;
    }
  else
    {
      socksinfo.socks_version_number = 4;
      socksinfo.command_code = SSH_SOCKS4_COMMAND_CODE_CONNECT;
      socksinfo.ip = (unsigned char *) c->next_address;
    }
  ssh_snprintf(host_port, sizeof(host_port), "%d", c->host_port);
  socksinfo.port = host_port;
  socksinfo.username = c->user_name;

  ssh_buffer_clear(c->socks_buf);



  SSH_FSM_SET_NEXT(tcp_connect_socks_send);
  if (socksinfo.ip == NULL)
    ret = SSH_SOCKS_ERROR_INVALID_ARGUMENT;

  if (ret == SSH_SOCKS_SUCCESS)
    ret = ssh_socks_client_generate_methods(c->socks_buf, &socksinfo);

  if (ret == SSH_SOCKS_SUCCESS)
    ret = ssh_socks_client_generate_open(c->socks_buf, &socksinfo);

  if (ret != SSH_SOCKS_SUCCESS)
    {
      if (next != NULL)
        {
          c->stream = NULL;
          ssh_stream_destroy(stream);
          c->next_address = next;
          SSH_FSM_SET_NEXT(tcp_connect_socks_lookup);
        }
      else
        {
          if (ret == SSH_SOCKS_ERROR_INVALID_ARGUMENT)
            c->error = SSH_TCP_NO_ADDRESS;
          else
            c->error = SSH_TCP_FAILURE;
          SSH_FSM_SET_NEXT(tcp_connect_finish);
        }
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(tcp_connect_socks_connect)
{
  ConnectContext c = (ConnectContext) fsm_context;

  SSH_DEBUG(5, ("Connecting SOCKS server %s:%u.", c->socks_next_address,
                c->socks_port));
  SSH_FSM_ASYNC_CALL(c->handle =
                     (*c->methods.connect_str)(c->methods_context,
                                             c->local_address,
                                             c->local_port,
                                             c->local_reusable,
                                             c->socks_next_address,
                                             c->socks_port,
                                             c->interface_index,
                                             c->routing_instance_id,
                                             &c->params,
                                             tcp_connect_socks_connect_done_cb,
                                             thread));
}

void tcp_connect_host_connect_done_cb(SshTcpError error,
                                      SshStream stream,
                                      void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  ConnectContext c = (ConnectContext) ssh_fsm_get_gdata(thread);

  c->handle = NULL;

  if (error != SSH_TCP_OK)
    {
      /* Get next address. */
      if (ssh_ustrchr(c->next_address, ','))
        c->next_address =
          ssh_ustrchr(c->next_address, ',') + 1;
      else
        { /* At end of list; consider it as a failure. */
          if (tcp_connect_register_failure(thread, error))
            {
              SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
              return;
            }
          c->next_address = c->host_addresses;
        }

      /* Try connecting again. */
      if (c->socks_host)
        {
          SSH_FSM_SET_NEXT(tcp_connect_socks_lookup);
        }
      /* If SOCKS is not used, we go back to tcp_connect_socks_connect */
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  c->stream = stream;
  /* Successfully connected to the host.  Call the user callback and
     destroy context. */
  SSH_FSM_SET_NEXT(tcp_connect_finish);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(tcp_connect_host_connect)
{
  ConnectContext c = (ConnectContext) fsm_context;

  SSH_FSM_ASYNC_CALL(c->handle =
                     (*c->methods.connect_str)(c->methods_context,
                                              c->local_address,
                                              c->local_port,
                                              c->local_reusable,
                                              c->next_address, c->host_port,
                                              c->interface_index,
                                              c->routing_instance_id,
                                              &c->params,
                                              tcp_connect_host_connect_done_cb,
                                              thread));
}

SSH_FSM_STEP(tcp_connect_socks_send)
{
  ConnectContext c = (ConnectContext) fsm_context;
  int len;

  do {
    len = ssh_stream_write(c->stream, ssh_buffer_ptr(c->socks_buf),
                           ssh_buffer_len(c->socks_buf));
    if (len > 0)
      ssh_buffer_consume(c->socks_buf, len);
    if (ssh_buffer_len(c->socks_buf) == 0)
      {
        SSH_FSM_SET_NEXT(tcp_connect_socks_receive_method);
        return SSH_FSM_CONTINUE;
      }
  } while (len > 0);

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(tcp_connect_socks_receive_read_byte)
{
  ConnectContext c = (ConnectContext) fsm_context;
  unsigned char buf[1];
  int len;

  len = ssh_stream_read(c->stream, buf, 1);

  if (len == 0)
    { /* Premature EOF received. */
      SSH_FSM_SET_NEXT(tcp_connect_socks_error);
      return SSH_FSM_CONTINUE;
    }
  if (len > 0)
    {
      if (ssh_buffer_append(c->socks_buf, buf, 1) != SSH_BUFFER_OK)
        {
          SSH_FSM_SET_NEXT(tcp_connect_socks_error);
          return SSH_FSM_CONTINUE;
        }
      SSH_FSM_SET_NEXT(c->next_state);
      return SSH_FSM_CONTINUE;
    }

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(tcp_connect_socks_receive_method)
{
  ConnectContext c = (ConnectContext) fsm_context;
  SocksError err;

  err = ssh_socks_client_parse_method(c->socks_buf, NULL);

  if (err == SSH_SOCKS_SUCCESS)
    {
      SSH_FSM_SET_NEXT(tcp_connect_socks_receive);
    }
  else if (err == SSH_SOCKS_TRY_AGAIN)
    {
      c->next_state = tcp_connect_socks_receive_method;
      SSH_FSM_SET_NEXT(tcp_connect_socks_receive_read_byte);
    }
  else
    {
      SSH_FSM_SET_NEXT(tcp_connect_socks_error);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(tcp_connect_socks_receive)
{
  ConnectContext c = (ConnectContext) fsm_context;
  SocksError err;

  err = ssh_socks_client_parse_reply(c->socks_buf, NULL);
  if (err != SSH_SOCKS_TRY_AGAIN)
    SSH_DEBUG(2, ("Got err = %d from "
                  "ssh_socks_client_parse_reply().", err));

  if (err == SSH_SOCKS_SUCCESS)
    {
      SSH_FSM_SET_NEXT(tcp_connect_finish);
    }
  else if (err == SSH_SOCKS_TRY_AGAIN)
    {
      c->next_state = tcp_connect_socks_receive;
      SSH_FSM_SET_NEXT(tcp_connect_socks_receive_read_byte);
    }
  else
    {
      SSH_FSM_SET_NEXT(tcp_connect_socks_error);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(tcp_connect_socks_error)
{
  ConnectContext c = (ConnectContext) fsm_context;

  ssh_stream_destroy(c->stream);
  c->stream = NULL;

  if (c->socks_type == SSH_TCP_SOCKS5 && !c->next_address)
    {
      c->error = SSH_TCP_FAILURE;
      SSH_FSM_SET_NEXT(tcp_connect_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Get the next host address. */
  if (ssh_ustrchr(c->next_address, ','))
    {
      c->next_address = ssh_ustrchr(c->next_address, ',') + 1;
    }
  else
    {
      if (tcp_connect_register_failure(thread, SSH_TCP_FAILURE))
        return SSH_FSM_CONTINUE;
      c->next_address = c->host_addresses;
    }
  if (c->socks_exceptions)
    {
      unsigned char *next;
      next = ssh_ustrchr(c->host_addresses, ',');
      if (next)
        *next = '\0';
      if (ssh_inet_compare_netmask(c->socks_exceptions,
                                   c->host_addresses))
        SSH_FSM_SET_NEXT(tcp_connect_host_connect);
      else
        SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
      if (next)
        *next = ',';
    }
  else
    {
      SSH_FSM_SET_NEXT(tcp_connect_socks_connect);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(tcp_connect_finish)
{
  ConnectContext c = (ConnectContext) fsm_context;

  if (c->error == SSH_TCP_OK)
    {
      /* Clear our callback function.  We don't want to get notifications
         for this stream anymore. */
      ssh_stream_set_callback(c->stream, NULL_FNPTR, NULL);
    }

  /* Call the user callback. */
  if (c->user_callback)
    (*c->user_callback)(c->error, c->stream, c->user_context);

  if (c->error == SSH_TCP_OK)
    {
      /* Prevent the stream from being freed when the context is freed. */
      c->stream = NULL;
    }
  SSH_FSM_SET_NEXT(tcp_connect_cleanup);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(tcp_connect_abort)
{
  ConnectContext c = (ConnectContext) fsm_context;
  c->upper_handle = NULL;
  SSH_FSM_SET_NEXT(tcp_connect_cleanup);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(tcp_connect_cleanup)
{
  ConnectContext c = (ConnectContext) fsm_context;
  ssh_fsm_destroy(c->fsm);
  tcp_connect_destroy_ctx(c);
  return SSH_FSM_FINISH;
}

/* Remove addresses that don't match the protocol match from the
   address list.  Overwrites the original list.  Can also result into
   empty address list. */

void ssh_remove_non_matching_addresses_from_list(unsigned char *address,
                                                 SshUInt32 protocol_mask)
{
  unsigned char *na, *cur, *next;

  if ((na = ssh_malloc(ssh_ustrlen(address) + 1)) == NULL)
    return;

  na[0] = '\0';
  cur = address;
  while (cur != NULL)
    {
      next = ssh_ustrchr(cur, ',');
      if (next)
        *next = '\0';
      if (ssh_address_type_matches_protocol_mask(cur, protocol_mask))
        {
          if (na[0] != '\0')
            {
              ssh_ustrcat(na, ssh_custr(","));
            }
          ssh_ustrcat(na, cur);
        }
      if (next)
        {
          cur = next + 1;
          *next = ',';
        }
      else
        {
          cur = NULL;
        }
    }

  SSH_DEBUG(5, ("Original address list = \"%s\"", address));
  ssh_ustrcpy(address, na);
  ssh_free(na);
  SSH_DEBUG(5, ("Fixed address list = \"%s\"", address));
  return;
}

/* Return TRUE, if address os of type that is specified in the
   protocol mask. */

Boolean ssh_address_type_matches_protocol_mask(unsigned char *address,
                                               SshUInt32 protocol_mask)
{
  SshIpAddrStruct ipaddr;
  Boolean pr;
  unsigned char *next;

  next = ssh_ustrchr(address, ',');
  if (next)
    *next = '\0';
  pr = ssh_ipaddr_parse(&ipaddr, address);
  if (next)
    *next = ',';
  if (! pr)
    return FALSE;
  if (SSH_IP_IS6(&ipaddr) && (protocol_mask & SSH_IP_TYPE_MASK_IP6))
    return TRUE;
  if (SSH_IP_IS4(&ipaddr) && (protocol_mask & SSH_IP_TYPE_MASK_IP4))
    return TRUE;
  return FALSE;
}


const char *ssh_tcp_error_string(SshTcpError error)
{
  switch (error)
    {
    case SSH_TCP_OK:
     return "OK";
    case SSH_TCP_NEW_CONNECTION:
     return "New TCP Connection";
    case SSH_TCP_NO_ADDRESS:
     return "No address associated to the name";
    case SSH_TCP_NO_NAME:
     return "No name associated to the address";
    case SSH_TCP_UNREACHABLE:
     return "Destination Unreachable";
    case SSH_TCP_REFUSED:
     return "Connection Refused";
    case SSH_TCP_TIMEOUT:
     return "Connection Timed Out";
    case SSH_TCP_FAILURE:
     return "TCP/IP Failure";
    default:
     return "Unknown Error";
    }
  /*NOTREACHED*/
}


Boolean ssh_tcp_has_ip_options(SshStream stream)
{
  SshTcpConnectMethods connect_methods;

  connect_methods =
    (SshTcpConnectMethods) ssh_stream_get_private_methods(stream);
  SSH_ASSERT(connect_methods != NULL);
  SSH_ASSERT(connect_methods->has_ip_options != NULL);

  return (*connect_methods->has_ip_options)(stream);
}

Boolean ssh_tcp_get_ip_addresses(SshStream stream,
                                 SshIpAddr local_ip,
                                 SshUInt16 *local_port,
                                 SshIpAddr remote_ip,
                                 SshUInt16 *remote_port)
{
  SshTcpConnectMethods connect_methods;

  connect_methods =
    (SshTcpConnectMethods) ssh_stream_get_private_methods(stream);
  if (connect_methods == FALSE)
    return FALSE;

  SSH_ASSERT(connect_methods->get_ip_addresses != NULL);
  return (*connect_methods->get_ip_addresses)(stream, local_ip, local_port,
                                              remote_ip, remote_port);
}

Boolean ssh_tcp_get_remote_address(SshStream stream, unsigned char *buf,
                                   size_t buflen)
{
  SshIpAddrStruct remote_ip;

  if (ssh_tcp_get_ip_addresses(stream, NULL, NULL, &remote_ip, NULL))
    {
      ssh_ipaddr_print(&remote_ip, buf, buflen);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_tcp_get_remote_port(SshStream stream, unsigned char *buf,
                                size_t buflen)
{
  SshUInt16 remote_port;

  if (ssh_tcp_get_ip_addresses(stream, NULL, NULL, NULL, &remote_port))
    {
      ssh_snprintf(buf, buflen, "%u", remote_port);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_tcp_get_local_address(SshStream stream, unsigned char *buf,
                                  size_t buflen)
{
  SshIpAddrStruct local_ip;

  if (ssh_tcp_get_ip_addresses(stream, &local_ip, NULL, NULL, NULL))
    {
      ssh_ipaddr_print(&local_ip, buf, buflen);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_tcp_get_local_port(SshStream stream, unsigned char *buf,
                                size_t buflen)
{
  SshUInt16 local_port;

  if (ssh_tcp_get_ip_addresses(stream, NULL, &local_port, NULL, NULL))
    {
      ssh_snprintf(buf, buflen, "%u", local_port);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_tcp_set_nodelay(SshStream stream, Boolean on)
{
  SshTcpConnectMethods connect_methods;

  connect_methods =
    (SshTcpConnectMethods) ssh_stream_get_private_methods(stream);
  SSH_ASSERT(connect_methods != NULL);
  SSH_ASSERT(connect_methods->set_nodelay != NULL);

  return (*connect_methods->set_nodelay)(stream, on);
}

Boolean ssh_tcp_set_keepalive(SshStream stream, Boolean on)
{
  SshTcpConnectMethods connect_methods;

  connect_methods =
    (SshTcpConnectMethods) ssh_stream_get_private_methods(stream);
  SSH_ASSERT(connect_methods != NULL);
  SSH_ASSERT(connect_methods->set_keepalive != NULL);

  return (*connect_methods->set_keepalive)(stream, on);
}

Boolean ssh_tcp_set_linger(SshStream stream, Boolean on)
{
  SshTcpConnectMethods connect_methods;

  connect_methods =
    (SshTcpConnectMethods) ssh_stream_get_private_methods(stream);
  SSH_ASSERT(connect_methods != NULL);
  SSH_ASSERT(connect_methods->set_linger != NULL);

  return (*connect_methods->set_linger)(stream, on);
}


struct SshTcpListenerRec
{
  SshTcpListenerMethodsStruct methods;
  void *methods_context;
  void *listener_context;
};

SshTcpListener
ssh_tcp_make_listener(const unsigned char *local_address,
                      const unsigned char *port_or_service,
                      int interface_index,
                      int routing_instance_id,
                      const SshTcpListenerParams params,
                      SshTcpCallback callback,
                      void *context)
{
  SshTcpListener listener;

  listener = ssh_calloc(1, sizeof(*listener));
  if (listener == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate memory for a new TCP listener"));
      return NULL;
    }

  if (params && params->tcp_listener_methods)
    {
      listener->methods = *params->tcp_listener_methods;
      listener->methods_context = params->tcp_listener_methods_context;
    }
  else
    {
      listener->methods =
        *ssh_tcp_listener_platform_methods(&listener->methods_context);
    }

  if (listener->methods.make_tcp_listener == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP listener methods"));
      ssh_free(listener);
      return NULL;
    }

  listener->listener_context =
    (*listener->methods.make_tcp_listener)(listener->methods_context,
                                           local_address,
                                           port_or_service,
                                           interface_index,
                                           routing_instance_id,
                                           params,
                                           callback,
                                           context);

  if (listener->listener_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create a new TCP listener"));
      ssh_free(listener);
      return NULL;
    }

  return listener;
}

SshTcpListener
ssh_tcp_make_listener_ip(SshIpAddr local_address,
                         SshUInt16 local_port,
                         int interface_index,
                         int routing_instance_id,
                         const SshTcpListenerParams params,
                         SshTcpCallback callback,
                         void *context)
{
  SshTcpListener listener;

  listener = ssh_calloc(1, sizeof(*listener));
  if (listener == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate memory for a new TCP listener"));
      return NULL;
    }

  if (params && params->tcp_listener_methods)
    {
      listener->methods = *params->tcp_listener_methods;
      listener->methods_context = params->tcp_listener_methods_context;
    }
  else
    {
      listener->methods =
        *ssh_tcp_listener_platform_methods(&listener->methods_context);
    }

  if (listener->methods.make_tcp_listener_ip == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP listener methods"));
      ssh_free(listener);
      return NULL;
    }

  listener->listener_context =
    (*listener->methods.make_tcp_listener_ip)(listener->methods_context,
                                              local_address,
                                              local_port,
                                              interface_index,
                                              routing_instance_id,
                                              params,
                                              callback,
                                              context);

  if (listener->listener_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create a new TCP listener"));
      ssh_free(listener);
      return NULL;
    }

  return listener;
}


SshUInt16
ssh_tcp_listener_get_local_port_number(SshTcpListener listener)
{
  if (listener->methods.get_tcp_local_port_number == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP listener methods"));
      return 0;
    }

  return (*listener->methods.get_tcp_local_port_number)
    (listener->methods_context, listener->listener_context);
}

Boolean
ssh_tcp_listener_get_local_port(SshTcpListener listener,
                                unsigned char *buf,
                                size_t buflen)
{
  SshUInt16 port;

  if (buf == NULL || buflen == 0)
    return FALSE;

  port = ssh_tcp_listener_get_local_port_number(listener);

  if (port == 0)
    return FALSE;

  ssh_snprintf(buf, buflen, "%u", port);
  return TRUE;
}

void
ssh_tcp_destroy_listener(SshTcpListener listener)
{
  if (listener->methods.destroy_tcp_listener == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid TCP listener methods"));
      ssh_free(listener);
      return;
    }

  (*listener->methods.destroy_tcp_listener)
    (listener->methods_context, listener->listener_context);

  ssh_free(listener);
}
