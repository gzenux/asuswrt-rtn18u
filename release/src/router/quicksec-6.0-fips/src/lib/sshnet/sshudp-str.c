/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic code of the UDP communications interface, string interface.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshudp.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshUdpGeneric"

/****************** Platform dependent UDP implementation *******************/

/* Fetch the platform dependent UDP methods and constructor
   context. */
SshUdpMethods ssh_udp_platform_methods(void **constructor_context_return);


/***************************** Public functions *****************************/

SshUdpListener
ssh_udp_make_listener(const unsigned char *local_address,
                      const unsigned char *local_port,
                      const unsigned char *remote_address,
                      const unsigned char *remote_port,
                      int interface_index,
                      int routing_instance_id,
                      SshUdpListenerParams params,
                      SshUdpCallback callback,
                      void *context)
{
  SshIpAddrStruct l_ip, r_ip;
  SshUInt16 l_port, r_port;
  SshInt32 port;

  SSH_IP_UNDEFINE(&l_ip); l_port = 0;
  if (local_address != NULL || local_port != NULL)
    {
      if (local_port != NULL)
        {
          port = ssh_inet_get_port_by_service(local_port, ssh_custr("udp"));
          if (port == -1)
            return NULL;
          l_port = port;
        }

      if (local_address != NULL && !SSH_IS_IPADDR_ANY(local_address))
        {
          /* Decode the IP address.  Host names are not accepted. */
          if (!ssh_ipaddr_parse(&l_ip, local_address))
            return NULL;
        }
    }

  SSH_IP_UNDEFINE(&r_ip); r_port = 0;
  if (remote_address != NULL || remote_port != NULL)
    {
      if (remote_port != NULL)
        {
          /* Look up the service name for the remote port. */
          port = ssh_inet_get_port_by_service(remote_port, ssh_custr("udp"));
          if (port == -1)
            return NULL;
          r_port = port;
        }

      if (remote_address != NULL)
        {
          /* Decode the IP address.  Host names are not accepted. */
          if (!ssh_ipaddr_parse(&r_ip, remote_address))
            return NULL;
        }
    }
  return ssh_udp_make_listener_ip(&l_ip, l_port,
                                  &r_ip, r_port,
                                  interface_index,
                                  routing_instance_id,
                                  params, callback, context);
}

SshUdpError
ssh_udp_read(SshUdpListener listener,
             unsigned char *remote_address, size_t remote_address_len,
             unsigned char *remote_port, size_t remote_port_len,
             unsigned char *datagram_buffer,
             size_t datagram_buffer_len,
             size_t *datagram_len_return)
{
  SshIpAddrStruct r_ip;
  SshUInt16 r_port;
  SshUdpError rv;

  rv = ssh_udp_read_ip(listener,
                       &r_ip, &r_port,
                       datagram_buffer, datagram_buffer_len,
                       datagram_len_return);

  if (rv == SSH_UDP_OK)
    {
      if (remote_address)
        ssh_ipaddr_print(&r_ip, remote_address, remote_address_len);
      if (remote_port)
        ssh_snprintf(remote_port, remote_port_len, "%d", r_port);
    }
  return rv;
}

SshUdpError
ssh_udp_send(SshUdpListener listener,
             const unsigned char *remote_address,
             const unsigned char *remote_port,
             const unsigned char *datagram_buffer, size_t datagram_len)
{
  SshIpAddrStruct r_ip;
  SshUInt16 r_port = 0;
  SshInt16 port;

  if (remote_port != NULL)
    {
      if ((port =
           ssh_inet_get_port_by_service(remote_port, ssh_custr("udp")))
          == -1)
        return SSH_UDP_INVALID_ARGUMENTS;

      r_port = port;
    }

  SSH_IP_UNDEFINE(&r_ip);
  if (remote_address != NULL)
    {
      if (!ssh_ipaddr_parse(&r_ip, remote_address))
        return SSH_UDP_INVALID_ARGUMENTS;
    }

  return ssh_udp_send_ip(listener,
                         &r_ip, r_port,
                         datagram_buffer, datagram_len);
}


SshUdpError
ssh_udp_multicast_add_membership(SshUdpListener listener,
                                 const unsigned char *group_to_join,
                                 const unsigned char *interface_to_join)
{
  SshIpAddrStruct g_ip, i_ip;

  SSH_IP_UNDEFINE(&g_ip);
  if (group_to_join)
    if (!ssh_ipaddr_parse(&g_ip, group_to_join))
      return SSH_UDP_INVALID_ARGUMENTS;

  SSH_IP_UNDEFINE(&i_ip);
  if (interface_to_join)
    if (!ssh_ipaddr_parse(&i_ip, interface_to_join))
      return SSH_UDP_INVALID_ARGUMENTS;

  return ssh_udp_multicast_add_membership_ip(listener, &g_ip, &i_ip);
}

SshUdpError
ssh_udp_multicast_drop_membership(SshUdpListener listener,
                                  const unsigned char *group_to_drop,
                                  const unsigned char *interface_to_drop)
{
  SshIpAddrStruct g_ip, i_ip;

  SSH_IP_UNDEFINE(&g_ip);
  if (group_to_drop)
    if (!ssh_ipaddr_parse(&g_ip, group_to_drop))
      return SSH_UDP_INVALID_ARGUMENTS;

  SSH_IP_UNDEFINE(&i_ip);
  if (interface_to_drop)
    if (!ssh_ipaddr_parse(&i_ip, interface_to_drop))
      return SSH_UDP_INVALID_ARGUMENTS;

  return ssh_udp_multicast_drop_membership_ip(listener, &g_ip, &i_ip);
}
