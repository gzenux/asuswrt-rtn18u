/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS Transport layer for UDP
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshudp.h"

#define SSH_DEBUG_MODULE "SshDnsTransportUdp"

/* Implementation specific structure. */
typedef struct SshDNSTransportUDPRec {
  SshUdpListener listener;
} *SshDNSTransportUDP, SshDNSTransportUDPStruct;

/* Receive function. */
void ssh_dns_transport_udp_receive(SshUdpListener listener, void *context)
{
  SshDNSTransportHost host = context;
  unsigned char *datagram;
  size_t datagram_len;
  SshUdpError error;

  SSH_DEBUG(SSH_D_LOWSTART, ("Received packet from connection %s",
                             ssh_dns_transport_host_name(host)));





  datagram_len = SSH_DNS_MAX_UDP_PACKET_SIZE;
  datagram = ssh_malloc(datagram_len);

  ssh_dns_transport_host_lock(host);

  if (datagram == NULL)
    {
      unsigned char buffer[4];

      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory error while allocating datagram buffer"));
      /* Ignore the packet, and return error. */
      error = ssh_udp_read_ip(listener,
                              NULL, NULL,
                              buffer, 4, &datagram_len);
      ssh_dns_transport_receive(SSH_DNS_MEMORY_ERROR, NULL, 0, host);
      ssh_dns_transport_host_unlock(host);
      return;
    }

  while (1)
    {
      datagram_len = SSH_DNS_MAX_UDP_PACKET_SIZE;
      /* We can ignore the remote_address as we know it (connected socket). */
      error = ssh_udp_read_ip(listener,
                              NULL, NULL,
                              datagram, datagram_len, &datagram_len);

      if (error == SSH_UDP_OK)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                            ("Received udp packet from connection %s",
                             ssh_dns_transport_host_name(host)),
                            datagram, datagram_len);
          ssh_dns_transport_receive(SSH_DNS_OK, datagram, datagram_len, host);
        }
      else if (error == SSH_UDP_NO_DATA)
        {
          /* No data, break out. */
          break;
        }
      else
        {
          /* Error, return UNREACHABLE. */
          SSH_DEBUG(SSH_D_FAIL, ("ssh_udp_read returned UDP error of %s (%d)",
                                 ssh_udp_error_string(error), error));
          ssh_dns_transport_receive(SSH_DNS_UNREACHABLE, NULL, 0, host);
          break;
        }
      /* Loop to next packet. */
    }
  ssh_dns_transport_host_unlock(host);
  ssh_free(datagram);
  return;
}

/* Lower layer transport open function. This function will
   open the connection to the given host and call callback
   when the connection is ready so the send function can be
   called. */
SshOperationHandle
ssh_dns_transport_udp_open(SshDNSTransportHost host,
                           void *implementation_data,
                           SshIpAddr from_ip, SshIpAddr to_ip,
                           SshDNSTransportHostCallback callback,
                           void *context)
{
  SshDNSTransportUDP impl = implementation_data;
  SshUdpListenerParams param = (SshUdpListenerParams)
              ssh_dns_transport_get_transport_param(host);

  SSH_DEBUG(SSH_D_LOWSTART, ("Opening udp connection %s",
                             ssh_dns_transport_host_name(host)));

  SSH_ASSERT(impl->listener == NULL);

  /* Note, we cannot use cryptographically strong random numbers directly here,
     as we cannot make forward reference from util library to the crypto
     library. We use random number callback here, which by default is ssh_rand,
     but which can be changed to ssh_random_get_uint32 by the application by
     calling ssh_dns_resolver_register_random_func function.  */
  impl->listener =
    ssh_udp_make_listener_ip(from_ip,
                             ssh_dns_transport_random_number(host)
                             % 64000 + 1024,
                             to_ip,
                             53,
                             -1,
                             0,
                             param,
                             ssh_dns_transport_udp_receive,
                             host);

  if (impl->listener == NULL)
    callback(SSH_DNS_UNABLE_TO_SEND, context);
  else
    callback(SSH_DNS_OK, context);
  return NULL;
}

/* Lower layer transport send function. This will send the packet. The
   connection must be open before this is called. If the lower layer cannot
   send packet at this time, then it should immediately call the callback with
   error code SSH_DNS_UNABLE_TO_SEND. If it managed to send partial packet, it
   MUST queue the rest of the packet to be transmitted for later (i.e. it needs
   to buffer up the one partial packet). Note, that lower layer can assume that
   packet buffer will remain constant during this operation, i.e. it will not
   be freed before the callback is called. */
SshOperationHandle
ssh_dns_transport_udp_send(SshDNSTransportHost host,
                           void *implementation_data,
                           const unsigned char *packet,
                           size_t packet_length,
                           SshUInt32 flags,
                           SshDNSTransportHostCallback callback,
                           void *context)
{
  SshDNSTransportUDP impl = implementation_data;
  SSH_ASSERT(impl->listener != NULL);

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Sending UDP packet to %s",
                                   ssh_dns_transport_host_name(host)),
                    packet, packet_length);

  ssh_udp_send_ip(impl->listener, NULL, 0, packet, packet_length);
  callback(SSH_DNS_OK, context);
  return NULL;
}

/* Lower layer transport close function. This function will
   close the connection to the given host. */
SshOperationHandle
ssh_dns_transport_udp_close(SshDNSTransportHost host,
                            void *implementation_data)
{
  SshDNSTransportUDP impl = implementation_data;
  SSH_ASSERT(impl->listener != NULL);
  ssh_udp_destroy_listener(impl->listener);
  impl->listener = NULL;
  SSH_DEBUG(SSH_D_LOWSTART, ("Udp connection %s closed",
                             ssh_dns_transport_host_name(host)));
  return NULL;
}



/* Specification structure. */
const
SshDNSTransportSpecStruct ssh_dns_transport_spec_udp_struct = {
  "UDP",
  sizeof(SshDNSTransportUDPStruct),
  ssh_dns_transport_udp_open,
  ssh_dns_transport_udp_send,
  ssh_dns_transport_udp_close
};

const SshDNSTransportSpecStruct *ssh_dns_transport_spec_udp =
  &ssh_dns_transport_spec_udp_struct;
