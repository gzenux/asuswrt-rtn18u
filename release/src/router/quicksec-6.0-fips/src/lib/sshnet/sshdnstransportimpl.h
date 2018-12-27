/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS Transport implementation layer
   This layer is used to implement specific transport over udp, tcp etc,
   or it can be used to hook in other methods of sending/receiving packets.
*/

#ifndef SSHDNSTRANSPORTIMPL_H
#define SSHDNSTRANSPORTIMPL_H

/**********************************************************************/
/* Lower layer protocol callbacks. This implements the
   protocol layer. */

/* Callback to open and close lower layer function. */
typedef void (*SshDNSTransportHostCallback)(SshDNSResponseCode error,
                                            void *context);

/* Lower layer transport open function. This function will
   open the connection to the given host and call callback
   when the connection is ready so the send function can be
   called. */
typedef SshOperationHandle (*SshDNSTransportHostOpenFunc)
     (SshDNSTransportHost host,
      void *implementation_data,
      SshIpAddr from_ip,
      SshIpAddr to_ip,
      SshDNSTransportHostCallback callback,
      void *context);

/* Lower layer transport send function. This will send the packet. The
   connection must be open before this is called. If the lower layer cannot
   send packet at this time, then it should immediately call the callback with
   error code SSH_DNS_UNABLE_TO_SEND. If it managed to send partial packet, it
   MUST queue the rest of the packet to be transmitted for later (i.e. it needs
   to buffer up the one partial packet). Note, that lower layer can assume that
   packet buffer will remain constant during this operation, i.e. it will not
   be freed before the callback is called. Flags are defined to be global for
   the whole dns library, i.e. same flags are given to the upper layer
   functions, and each layer can allocate flags from their own bitmask, see
   sshdns.h for details. */
typedef SshOperationHandle (*SshDNSTransportHostSendFunc)
     (SshDNSTransportHost host,
      void *implementation_data,
      const unsigned char *packet,
      size_t packet_length,
      SshUInt32 flags,
      SshDNSTransportHostCallback callback,
      void *context);

/* Lower layer transport close function. This function will
   close the connection to the given host. */
typedef SshOperationHandle (*SshDNSTransportHostCloseFunc)
     (SshDNSTransportHost host, void *implementation_data);

/* Transport specification structure. */
typedef struct SshDNSTransportSpecRec {
  /* The host structure will contain implementation specific data appended to
     it, allocated with same malloc. This will tell the size of that
     implementation specific data, and the lower layer will get object of this
     size as argument to all functions. */
  const char *name;
  size_t size_of_implemenation_structure;
  SshDNSTransportHostOpenFunc open_function;
  SshDNSTransportHostSendFunc send_function;
  SshDNSTransportHostCloseFunc close_function;
} *SshDNSTransportSpec, SshDNSTransportSpecStruct;

/* This function is called by the lower layer when it
   receives a packet. This can also be called with error
   code, which means there was an error. The upper layer
   will automatically close the connection after receiving
   error code. If the error is anything else than SSH_DNS_OK
   then received_packet will be NULL and packet_length will
   be zero. The received_packet must be complete dns packet
   as received from the transport, i.e. the lower layer must
   wait until it gets one complete packet, and remove any
   outer wrappings from the packet before giving it out.
   This function can only be called when the connection is
   open. The received_packet needs only be valid during the
   call to this function. The host must be locked before
   calling this function. */
void ssh_dns_transport_receive(SshDNSResponseCode error,
                               const unsigned char *received_packet,
                               size_t packet_length,
                               SshDNSTransportHost host);

#endif /* SSHDNSTRANSPORTIMPL_H */
