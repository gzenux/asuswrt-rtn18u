/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Portable interface for UDP communications.  (The implementation is
   machine-dependent, but provides this interface on all platforms.)

   Two paraller API's. One that takes in addresses as strings and
   allows use of domain names, and other lower level that takes in IP
   addresses.
*/

#ifndef SSHUDP_H
#define SSHUDP_H

#include "sshinet.h"

/** Data type for an UDP listener. */
typedef struct SshUdpListenerRec *SshUdpListener;

/** A forward declaration for UDP listener parameters. */
typedef struct SshUdpListenerParamsRec *SshUdpListenerParams;

/** Callback function to be called when a packet or notification is
    available from the udp listener.  ssh_udp_read should be called
    from the callback. */
typedef void (*SshUdpCallback)(SshUdpListener listener, void *context);

/** Error codes for UDP operations. */
typedef enum
{
  /** A packet was successfully read from the listener. */
  SSH_UDP_OK,

  /** A host or network unreachable notification was received. */
  SSH_UDP_HOST_UNREACHABLE,

  /** A port unreachable notification was received. */
  SSH_UDP_PORT_UNREACHABLE,

  /** No packet or notification is available from the listener at this time. */
  SSH_UDP_NO_DATA,

  /** Invalid arguments. */
  SSH_UDP_INVALID_ARGUMENTS
} SshUdpError;

extern const SshKeywordStruct ssh_udp_status_keywords[];

/** Methods for hooking UDP listeners and for different UDP
    implementations. */
struct SshUdpMethodsRec
{
  /** Create a new listener.

      @param make_listener_method_context
      The context data that was specified for the method
      functions with the 'make_listener_method_context' field of
      SshUdpListenerParamsStruct.

      @return
      The function must return a new listener object or NULL if
      the listener creation fails.  The returned listener object
      is passed as the 'listener_context' for all other methods.

      */
  void *(*make_listener)(void *make_listener_method_context,
                         SshUdpListener listener,
                         SshIpAddr local_address,
                         SshUInt16 local_port,
                         SshIpAddr remote_address,
                         SshUInt16 remote_port,
                         int interface_index,
                         int routing_instance_id,
                         SshUdpListenerParams params,
                         SshUdpCallback callback,
                         void *callback_context);

  /** Destroy the listener object 'listener_context'. */
  void (*destroy_listener)(void *listener_context);

  /** Implements the read operation.

      @param listener_context
      Identifies the UDP listener object from which the data is
      read.

      */
  SshUdpError (*read)(void *lister_context,
                      SshIpAddr remote_address, SshUInt16 *remote_port,
                      unsigned char *datagram_buffer,
                      size_t datagram_buffer_len,
                      size_t *datagram_len_return);

  /** Implements the send operation.

      @param lister_context
      Identifies the UDP listener that is sending data.

      */
  SshUdpError (*send)(void *listener_context,
                      SshIpAddr remote_address, SshUInt16 remote_port,
                      const unsigned char *datagram_buffer,
                      size_t datagram_len);

  /** Implements the multicast group join operation.

      @param listener_context
      Identifies the UDP listener that is joining to the multicast
      group.

      */
  SshUdpError (*multicast_add_membership)(void *listener_context,
                                          SshIpAddr group_to_join,
                                          SshIpAddr interface_to_join);

  /** Implements the multicast group leave operation.

      @param listener_context
      Identifies the UDP listener that is leaving from the multicast
      group.

      */
  SshUdpError (*multicast_drop_membership)(void *listener_context,
                                           SshIpAddr group_to_join,
                                           SshIpAddr interface_to_drop);

  Boolean (*get_ip_addresses)(void *listener_context,
                              SshIpAddr local_ip,
                              SshUInt16 *local_port,
                              SshIpAddr remote_ip,
                              SshUInt16 *remote_port);
};

typedef struct SshUdpMethodsRec SshUdpMethodsStruct;
typedef struct SshUdpMethodsRec *SshUdpMethods;

/** Parameters for the ssh_udp_make_listener function.  If any of the
    fields has the value NULL or 0, the default value will be used
    instead. */
struct SshUdpListenerParamsRec
{
  /** The listener has permission to send broadcast packets. */
  Boolean broadcasting;

  /** Multicast hop count limit (TTL) - this affects when sending
      multicast traffic from the socket; you don't need to be part of
      the multicast group to send packets to it. */
  SshUInt32 multicast_hops;

  /** Enable/disable multicast looping in the local host - if this is
      enabled, then multicast sent from this socket is looped back
      inside the machine to all sockets that are member of the
      multicast group; normally this is enabled, which means that all
      processes (including you) in this host that are part of the group
      can also hear your tranmissions; if you are sure that you are
      only member in this host, you can disable this saving you time to
      process your own multicast packets. */
  Boolean multicast_loopback;

  /** Optional methods for the UDP implementation - if these are set,
      they are used for all UDP operations with the created listener;
      if the methods are unset, the platform specific UDP
      implementation will be used instead. */
  SshUdpMethods udp_methods;

  /** Context data for the 'make_listener' method, defined in
      'udp_methods'. */
  void *make_listener_method_context;
};

typedef struct SshUdpListenerParamsRec SshUdpListenerParamsStruct;

/** Creates a listener for sending and receiving UDP packets.
    The listener is connected if remote_address is non-NULL.
    Connected listeners may receive notifications about the
    destination host/port being unreachable.

    @param local_address
    Local address for sending; SSH_IPADDR_ANY chooses automatically.

    @param local_port
    Local port for receiving UDP packets (NULL lets system pick one).

    @param remote_address
    Specifies the remote address for this listener is non-NULL - if
    specified, unreachable notifications may be received for packets
    sent to the address.

    @param remote_port
    Remote port for packets sent using this listener, or NULL.

    @param interface_index
    Speficies the interface index for this listener, or -1 if not used.

    @param routing_instance_id
    Speficies the routing instance id for this listener.

    @param params
    Additional paameters for the listener - this can be NULL in which
    case the default parameters are used.

    @param callback
    Function to call when packet or notification available.

    @param context
    Argument to pass to the callback.

    @return
    This returns the listener, or NULL if the listener could not be
    created (e.g., due to a resource shortage or unparsable address).

  */
SshUdpListener
ssh_udp_make_listener(const unsigned char *local_address,
                      const unsigned char *local_port,
                      const unsigned char *remote_address,
                      const unsigned char *remote_port,
                      int interface_index,
                      int routing_instance_id,
                      SshUdpListenerParams params,
                      SshUdpCallback callback,
                      void *context);

/** Creates a listener for sending and receiving UDP packets.
    The listener is connected if remote_address is non-NULL.
    Connected listeners may receive notifications about the
    destination host/port being unreachable.

    @param local_address
    Local address for sending; SSH_IPADDR_ANY chooses automatically.

    @param local_port
    Local port for receiving UDP packets (NULL lets system pick one).

    @param remote_address
    Specifies the remote address for this listener is non-NULL - if
    specified, unreachable notifications may be received for packets
    sent to the address.

    @param remote_port
    Remote port for packets sent using this listener, or NULL.

    @param interface_index
    Speficies the interface index for this listener, or -1 if not used.

    @param routing_instance_id
    Speficies the routing instance id for this listener.

    @param params
    Additional paameters for the listener - this can be NULL in which
    case the default parameters are used.

    @param callback
    Function to call when packet or notification available.

    @param context
    Argument to pass to the callback.

    @return
    This returns the listener, or NULL if the listener could not be
    created (e.g., due to a resource shortage or unparsable address).

  */
SshUdpListener
ssh_udp_make_listener_ip(SshIpAddr local_address,
                         SshUInt16 local_port,
                         SshIpAddr remote_address,
                         SshUInt16 remote_port,
                         int interface_index,
                         int routing_instance_id,
                         SshUdpListenerParams params,
                         SshUdpCallback callback,
                         void *context);

/** Destroys the UDP listener. */
void ssh_udp_destroy_listener(SshUdpListener listener);

/** Convert UDP error to string. */
const char *ssh_udp_error_string(SshUdpError error);

/** Reads the received packet or notification from the listener.  This
    function should be called from the listener callback.  This can be
    called multiple times from a callback; each call will read one more
    packet or notification from the listener until no more are
    available. */
SshUdpError
ssh_udp_read(SshUdpListener listener,
             unsigned char *remote_address, size_t remote_address_len,
             unsigned char *remote_port, size_t remote_port_len,
             unsigned char *datagram_buffer,
             size_t datagram_buffer_len,
             size_t *datagram_len_return);

/** Reads the received packet or notification from the listener.  This
    function should be called from the listener callback.  This can be
    called multiple times from a callback; each call will read one more
    packet or notification from the listener until no more are
    available. */
SshUdpError
ssh_udp_read_ip(SshUdpListener listener,
                SshIpAddr remote_address, SshUInt16 *remote_port,
                unsigned char *datagram_buffer,
                size_t datagram_buffer_len,
                size_t *datagram_len_return);

/** Returns pointer to a global datagram buffer large
    enough to hold maximum sized UDP packet (there is one such
    buffer).

    Consistency management for this buffer is the application's
    responsibility. As a general principle, references to this should
    be considered invalid after returning to the bottom of the event
    loop.

    Application must not free the buffer. */
unsigned char *
ssh_udp_get_datagram_buffer(size_t *datagram_buffer_len);

/** This sends an UDP datagram to remote destination. */
SshUdpError
ssh_udp_send(SshUdpListener listener,
             const unsigned char *remote_address,
             const unsigned char *remote_port,
             const unsigned char *datagram_buffer,
             size_t datagram_len);

/** This sends an UDP datagram to remote destination. */
SshUdpError
ssh_udp_send_ip(SshUdpListener listener,
                SshIpAddr remote_address, SshUInt16 remote_port,
                const unsigned char *datagram_buffer,
                size_t datagram_len);

/** Add membership to given multicast group.

    If the group_to_join is an ipv4 address then this function joins
    to the ipv4 multicast group. If it is ipv6 address then we join to
    the ipv6 address (in which case the listener must be one listening
    ipv6 address or SSH_IPADDR_ANY.

    You don't need to be part of the multicast group to send
    packets to it.

    @param group_to_join
    The group to join is an IP address of the multicast group you want
    to join.

    @param interface_to_join
    The interface to join can be an IP address of the interface, if
    you want to join to that group only in one interface, or
    SSH_IPADDR_ANY, if you want to listen all interfaces.

    */
SshUdpError
ssh_udp_multicast_add_membership(SshUdpListener listener,
                                 const unsigned char *group_to_join,
                                 const unsigned char *interface_to_join);

/** Add membership to given multicast group.

    If the group_to_join is an ipv4 address then this function joins
    to the ipv4 multicast group. If it is ipv6 address then we join to
    the ipv6 address (in which case the listener must be one listening
    ipv6 address or SSH_IPADDR_ANY.

    You don't need to be part of the multicast group to send
    packets to it.

    @param group_to_join
    The group to join is an IP address of the multicast group you want
    to join.

    @param interface_to_join
    The interface to join can be an IP address of the interface, if
    you want to join to that group only in one interface, or
    SSH_IPADDR_ANY, if you want to listen all interfaces.

    */
SshUdpError
ssh_udp_multicast_add_membership_ip(SshUdpListener listener,
                                    SshIpAddr group_to_join,
                                    SshIpAddr interface_to_join);

/** Drop membership to given multicast group.

    @param group_to_drop
    The group to drop is an IP address of the multicast group you want
    to drop.

    @param interface_to_drop
    The interface to drop can be IP address of the interface, if
    you want to drop to that group only in one interface, or
    SSH_IPADDR_ANY, if you want to drop listening in all
    interfaces. Normally interface_to_drop is same value that was
    used in the ssh_udp_multicast_add_membership function.

    */
SshUdpError
ssh_udp_multicast_drop_membership(SshUdpListener listener,
                                  const unsigned char *group_to_drop,
                                  const unsigned char *interface_to_drop);

/** Drop membership to given multicast group.

    @param group_to_drop
    The group to drop is an IP address of the multicast group you want
    to drop.

    @param interface_to_drop
    The interface to drop can be IP address of the interface, if
    you want to drop to that group only in one interface, or
    SSH_IPADDR_ANY, if you want to drop listening in all
    interfaces. Normally interface_to_drop is same value that was
    used in the ssh_udp_multicast_add_membership function.

    */
SshUdpError
ssh_udp_multicast_drop_membership_ip(SshUdpListener listener,
                                     SshIpAddr group_to_drop,
                                     SshIpAddr interface_to_drop);


/* Fetch IP addresses and ports for the UDP listener. Any of the return
   value paratemers `local_ip', `local_port', `remote_ip'or `remote_port'
   may be NULL. On success this sets the value of each non-NULL return value
   parameter and returns TRUE. On error this returns FALSE and the values of
   the return value parameters are unspecified. */
Boolean
ssh_udp_get_ip_addresses(SshUdpListener listener,
                         SshIpAddr local_ip,
                         SshUInt16 *local_port,
                         SshIpAddr remote_ip,
                         SshUInt16 *remote_port);
#endif /* SSHUDP_H */
