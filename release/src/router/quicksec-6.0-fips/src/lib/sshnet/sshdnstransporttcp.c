/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS Transport layer for TCP
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshtcp.h"
#include "sshbuffer.h"

#define SSH_DEBUG_MODULE "SshDnsTransportTcp"

#define SSH_DNS_TCP_BUFLEN 1024

typedef enum {
  SSH_DNS_TRANSPORT_TCP_SEND_LENGTH,
  SSH_DNS_TRANSPORT_TCP_SEND_LENGTH_2ND_BYTE,
  SSH_DNS_TRANSPORT_TCP_SEND_DATA
} SshDNSTransportTCPState;

/* Implementation specific structure. */
typedef struct SshDNSTransportTCPRec {
  /* TCP/IP stream. If this is NULL then the connection is already closed.  */
  SshStream tcp_stream;
  /* Buffer for incoming data. */
  SshBuffer input_buffer;
  /* Callback and context to call after the open or send operation is done. */
  SshDNSTransportHostCallback callback;
  void *context;
  /* Packet and packet_length we are sending out. */
  const unsigned char *packet;
  size_t packet_length;
  /* State of the sending. */
  SshDNSTransportTCPState state;
  /* Operation handle. */
  SshOperationHandleStruct operation_handle[1];
  /* Descructor object. */
  SshOperationDestructorStruct destructor_context[1];
  /* Pointer back to the host. */
  SshDNSTransportHost host;
} *SshDNSTransportTCP, SshDNSTransportTCPStruct;

/* Receive function. Check data on the socket. */
void ssh_dns_transport_tcp_receive(SshDNSTransportTCP impl)
{
  unsigned char *p;
  size_t l, packet_length;

  while (1)
    {
      p = ssh_buffer_ptr(impl->input_buffer);
      l = ssh_buffer_len(impl->input_buffer);
      if (l < 2)
        return;

      packet_length = SSH_GET_16BIT(p);
      if (l < packet_length + 2)
        return;

      ssh_dns_transport_host_lock(impl->host);
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("Received tcp packet from connection %s",
                         ssh_dns_transport_host_name(impl->host)),
                        p + 2, packet_length);
      ssh_dns_transport_receive(SSH_DNS_OK, p + 2, packet_length, impl->host);
      ssh_buffer_consume(impl->input_buffer, 2 + packet_length);
      ssh_dns_transport_host_unlock(impl->host);
    }
}

/* Callback to call when there is data available on the socket, or when we have
   data we can write to the socket. */
void ssh_dns_transport_tcp_callback(SshStreamNotification notification,
                                    void *context)
{
  SshDNSTransportTCP impl = context;
  unsigned char buffer[2];
  unsigned char *p;
  int l;

  switch (notification)
    {
    case SSH_STREAM_CAN_OUTPUT:
      /* Do we have packet to send. */
      if (impl->packet_length == 0)
        return;
      /* Yes */
      while (impl->packet_length > 0)
        {
          if (impl->state == SSH_DNS_TRANSPORT_TCP_SEND_LENGTH)
            {
              SSH_PUT_16BIT(buffer, impl->packet_length);
              l = ssh_stream_write(impl->tcp_stream, buffer, 2);
            }
          else if (impl->state == SSH_DNS_TRANSPORT_TCP_SEND_LENGTH_2ND_BYTE)
            {
              SSH_PUT_16BIT(buffer, impl->packet_length);
              l = ssh_stream_write(impl->tcp_stream, buffer + 1, 1);
            }
          else
            {
              l = ssh_stream_write(impl->tcp_stream, impl->packet,
                                   impl->packet_length);
            }
          if (l == 0)
            {
              /* EOF, the server has closed the connection. Return error. */
              (*impl->callback)(SSH_DNS_UNABLE_TO_SEND, impl->context);
              goto clear_packet;
            }
          if (l < 0)
            {
              SSH_DEBUG(SSH_D_LOWSTART, ("Write blocked"));
              return;
            }
          if (impl->state == SSH_DNS_TRANSPORT_TCP_SEND_LENGTH)
            {
              if (l == 1)
                impl->state = SSH_DNS_TRANSPORT_TCP_SEND_LENGTH_2ND_BYTE;
              else
                impl->state = SSH_DNS_TRANSPORT_TCP_SEND_DATA;
            }
          else if (impl->state == SSH_DNS_TRANSPORT_TCP_SEND_LENGTH_2ND_BYTE)
            {
              impl->state = SSH_DNS_TRANSPORT_TCP_SEND_DATA;
            }
          else
            {
              /* Wrote some stuff, remove it from buffer. */
              impl->packet_length -= l;
              impl->packet += l;
            }
        }
      /* Wrote everything. */
      (*impl->callback)(SSH_DNS_OK, impl->context);
    clear_packet:
      /* Unregister the operation. */
      ssh_operation_unregister(impl->operation_handle);
      impl->callback = NULL;
      impl->context = NULL;
      impl->packet = NULL;
      impl->packet_length = 0;
      return;
    case SSH_STREAM_INPUT_AVAILABLE:
      /* Read data from socket. */
      while (1)
        {
          (void)ssh_buffer_append_space(impl->input_buffer,
                                        &p, SSH_DNS_TCP_BUFLEN);
          l = ssh_stream_read(impl->tcp_stream, p, SSH_DNS_TCP_BUFLEN);
          if (l < 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Read blocked"));
              ssh_buffer_consume_end(impl->input_buffer, SSH_DNS_TCP_BUFLEN);
              return;
            }
          if (l == 0)
            {
              SSH_DEBUG(SSH_D_HIGHSTART, ("Eof received"));
              ssh_buffer_consume_end(impl->input_buffer, SSH_DNS_TCP_BUFLEN);
              ssh_stream_destroy(impl->tcp_stream);
              impl->tcp_stream = NULL;
              return;
            }

          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Data from network"), p, l);
          ssh_buffer_consume_end(impl->input_buffer, SSH_DNS_TCP_BUFLEN - l);
          /* Try to parse the data. */
          ssh_dns_transport_tcp_receive(impl);
        }
    case SSH_STREAM_DISCONNECTED:
      SSH_DEBUG(SSH_D_HIGHSTART, ("Disconnected"));
      impl->tcp_stream = NULL;
      break;
    }
}

/* Callback to call when connection to the server is ready. */
void ssh_dns_transport_tcp_connect(SshTcpError error,
                                   SshStream stream,
                                   void *context)
{
  SshDNSTransportTCP impl = context;
  SshDNSResponseCode code;

  if (error == SSH_TCP_OK)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Tcp connection open to %s.",
                                 ssh_dns_transport_host_name(impl->host)));
      impl->tcp_stream = stream;
      code = SSH_DNS_OK;
      ssh_stream_set_callback(impl->tcp_stream,
                              ssh_dns_transport_tcp_callback,
                              (void *)impl);
    }
  else
    {
      ssh_buffer_free(impl->input_buffer);
      impl->input_buffer = NULL;
      SSH_DEBUG(SSH_D_FAIL,
                ("ssh_tcp_connect_ip to %s returned TCP error of %s (%d)",
                 ssh_dns_transport_host_name(impl->host),
                 ssh_tcp_error_string(error), error));
      code = SSH_DNS_REFUSED;
    }
  (*impl->callback)(code, impl->context);
  impl->callback = NULL;
  impl->context = NULL;
  return;
}

void ssh_dns_transport_tcp_destructor(Boolean aborted,
                                      void *context)
{
  SshDNSTransportTCP impl = context;

  if (aborted)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Tcp connect was aborted %s",
                                 ssh_dns_transport_host_name(impl->host)));
      impl->callback = NULL;
      impl->context = NULL;
      ssh_buffer_free(impl->input_buffer);
      impl->input_buffer = NULL;
    }
  return;
}

/* Lower layer transport open function. This function will
   open the connection to the given host and call callback
   when the connection is ready so the send function can be
   called. */
SshOperationHandle
ssh_dns_transport_tcp_open(SshDNSTransportHost host,
                           void *implementation_data,
                           SshIpAddr from_ip, SshIpAddr to_ip,
                           SshDNSTransportHostCallback callback,
                           void *context)
{
  SshDNSTransportTCP impl = implementation_data;
  SshOperationHandle handle;
  SshTcpConnectParams param = (SshTcpConnectParams)
                ssh_dns_transport_get_transport_param(host);

  SSH_DEBUG(SSH_D_LOWSTART, ("Opening tcp connection %s",
                             ssh_dns_transport_host_name(host)));

  SSH_ASSERT(impl->tcp_stream == NULL);
  SSH_ASSERT(impl->input_buffer == NULL);
  impl->input_buffer = ssh_buffer_allocate();
  if (impl->input_buffer == NULL)
    {
      callback(SSH_DNS_MEMORY_ERROR, context);
      return NULL;
    }
  impl->callback = callback;
  impl->context = context;
  impl->host = host;

  /* Note, we cannot use cryptographically strong random numbers directly here,
     as we cannot make forward reference from util library to the crypto
     library. We use random number callback here, which by default is ssh_rand,
     but which can be changed to ssh_random_get_uint32 by the application by
     calling ssh_dns_resolver_register_random_func function.  */
  handle = ssh_tcp_connect_ip(to_ip, 53, from_ip,
                              ssh_dns_transport_random_number(host)
                              % 64000 + 1024,
                              -1,
                              0,
                              param,
                              ssh_dns_transport_tcp_connect,
                              impl);

  ssh_operation_attach_destructor_no_alloc(impl->destructor_context,
                                           handle,
                                           ssh_dns_transport_tcp_destructor,
                                           impl);
  return handle;
}

/* Abort callback for the ssh_dns_transport_tcp_send. If we abort the
   operation, we need to also close the connection, as we do not know how much
   the other end have received of our packet. */
void ssh_dns_transport_tcp_abort(void *context)
{
  SshDNSTransportTCP impl = context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Abortting tcp send %s",
                             ssh_dns_transport_host_name(impl->host)));
  impl->callback = NULL;
  impl->context = NULL;
  impl->packet = NULL;
  impl->packet_length = 0;
  ssh_stream_destroy(impl->tcp_stream);
  impl->tcp_stream = NULL;
  return;
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
ssh_dns_transport_tcp_send(SshDNSTransportHost host,
                           void *implementation_data,
                           const unsigned char *packet,
                           size_t packet_length,
                           SshUInt32 flags,
                           SshDNSTransportHostCallback callback,
                           void *context)
{
  SshDNSTransportTCP impl = implementation_data;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Sending TCP packet to %s",
                                   ssh_dns_transport_host_name(host)),
                    packet, packet_length);

  /* If we have packet already in queue, or we do not have stream open anymore,
     return error. */
  if (impl->packet_length > 0 || impl->tcp_stream == NULL)
    {
      callback(SSH_DNS_UNABLE_TO_SEND, context);
      return NULL;
    }
  /*  Queue up the packet. */
  impl->packet = packet;
  impl->packet_length = packet_length;
  impl->callback = callback;
  impl->context = context;
  impl->state = SSH_DNS_TRANSPORT_TCP_SEND_LENGTH;
  /* Create operation handle. */
  ssh_operation_register_no_alloc(impl->operation_handle,
                                  ssh_dns_transport_tcp_abort,
                                  impl);
  /* Try to send the packet. */
  ssh_dns_transport_tcp_callback(SSH_STREAM_CAN_OUTPUT, impl);
  /* Check if we managed to send all stuff. */
  if (impl->packet_length == 0)
    return NULL;
  /* We didn't send it immediately, so return operation handle. */
  return impl->operation_handle;
}

/* Lower layer transport close function. This function will
   close the connection to the given host. */
SshOperationHandle
ssh_dns_transport_tcp_close(SshDNSTransportHost host,
                            void *implementation_data)
{
  SshDNSTransportTCP impl = implementation_data;

  if (impl->tcp_stream != NULL)
    ssh_stream_destroy(impl->tcp_stream);
  impl->tcp_stream = NULL;
  ssh_buffer_free(impl->input_buffer);
  impl->input_buffer = NULL;
  SSH_DEBUG(SSH_D_LOWSTART, ("Tcp connection %s closed",
                             ssh_dns_transport_host_name(host)));
  return NULL;
}


/* Specification structure. */
const
SshDNSTransportSpecStruct ssh_dns_transport_spec_tcp_struct = {
  "TCP",
  sizeof(SshDNSTransportTCPStruct),
  ssh_dns_transport_tcp_open,
  ssh_dns_transport_tcp_send,
  ssh_dns_transport_tcp_close
};

const SshDNSTransportSpecStruct *ssh_dns_transport_spec_tcp =
  &ssh_dns_transport_spec_tcp_struct;
