/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec over TCP encapsulation.
*/

#ifdef SSH_IPSEC_TCPENCAP


#ifndef ENGINE_TCP_ENCAPS_H
#define ENGINE_TCP_ENCAPS_H 1

/** Connection hash table size. */
#define SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE 64

/** Maximum value for the conn_id value. */
#define SSH_ENGINE_TCP_ENCAPS_MAX_CONN_ID \
(65536 * SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE)

#ifndef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
/* TCP connection states. */
/* Copied from the engine_tcp.h file. */
typedef enum {
  SSH_ENGINE_TCP_INITIAL,
  SSH_ENGINE_TCP_SYN,
  SSH_ENGINE_TCP_SYN_ACK,
  SSH_ENGINE_TCP_SYN_ACK_ACK,
  SSH_ENGINE_TCP_ESTABLISHED,
  SSH_ENGINE_TCP_FIN_FWD,
  SSH_ENGINE_TCP_FIN_REV,
  SSH_ENGINE_TCP_FIN_FIN,
  SSH_ENGINE_TCP_CLOSE_WAIT,
  SSH_ENGINE_TCP_CLOSED
} SshEngineTcpState;
#else /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
#include "engine_tcp.h"
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

/** The length of an IKE cookie. */
#define SSH_ENGINE_IKE_COOKIE_LENGTH 8

/* ***************** IPsec over TCP encapsulation trailer ********************/

/** The length of the magic cookie in TCP trailer. */
#define SSH_ENGINE_TCP_ENCAPS_COOKIE_LEN 4

/** The magic constant cookie value. */
#define SSH_ENGINE_TCP_ENCAPS_COOKIE_VALUE "\x21\x45\x6c\x69"

/* ***************** Timeouts ************************************************/

/** TCP handshake timeout, in seconds. */
#define SSH_ENGINE_TCP_ENCAPS_INITIAL_TIMEOUT 3

/** IKE negotiation timeout, in seconds. */
#define SSH_ENGINE_TCP_ENCAPS_NEGOTIATION_TIMEOUT 60

/** Connection close timeout, in microseconds. */
#define SSH_ENGINE_TCP_ENCAPS_CLOSE_TIMEOUT 500000

/* ***************** Port ranges *********************************************/

/** The low end of the range from which the local TCP port is randomly
    selected if it is not specified in the configuration. */
#define SSH_ENGINE_TCP_ENCAPS_LOCAL_PORT_MIN 1024

/** The high end of the range from which the local TCP port is randomly
    selected if it is not specified in the configuration. */
#define SSH_ENGINE_TCP_ENCAPS_LOCAL_PORT_MAX 65535

/* ***************** Encapsulating TCP connection table entry ****************/

/** The maximum number of IPsec SAs over a single encapsulating
    TCP connection. */
#define SSH_ENGINE_TCP_ENCAPS_MAX_SAS 16

/** Encapsulating TCP connection. */
typedef struct SshEngineTcpEncapsConnRec
{
  struct SshEngineTcpEncapsConnRec *next;
  struct SshEngineTcpEncapsConnRec *timeout_next;

  /** Back pointer to Engine. */
  SshEngine engine;

  /** Connection identifier. */
  SshUInt32 conn_id;

  /** TCP connection: local address. */
  SshIpAddrStruct local_addr;
  /** TCP connection: local port. */
  SshUInt16 local_port;
  /** TCP connection: peer address. */
  SshIpAddrStruct peer_addr;
  /** TCP connection: peer port. */
  SshUInt16 peer_port;
  /** TCP connection: seq. */
  SshUInt32 seq;
  /** TCP connection: ack. */
  SshUInt32 ack;
  /** TCP connection: state. */
  SshEngineTcpState state;

  /** The IKE packet that triggered the TCP handshake. */
  SshInterceptorPacket trigger_packet;

  /** Connection is in initial timeout list. */
  SshUInt8 in_initial_timeout_list : 1;
  /** Connection is in negotiation timeout list. */
  SshUInt8 in_negotiation_timeout_list : 1;
  /** Negotiation completed. */
  SshUInt8 negotiation_completed : 1;
  /** IKE cookie mapping is set. */
  SshUInt8 ike_mapping_set : 1;

  /** TCP trailer. */
  SshUInt32 trailer_seq;
  /** TCP trailer cookie. */
  unsigned char cookie[SSH_ENGINE_TCP_ENCAPS_COOKIE_LEN];

  /** Configured local port. */
  SshUInt16 configured_local_port;

  /** IKE ports. */
  SshUInt16 local_ike_port;
  SshUInt16 remote_ike_port;

  /** IKE initiator cookie. */
  unsigned char ike_initiator_cookie[SSH_ENGINE_IKE_COOKIE_LENGTH];
  /** Old IKE initiator cookie. */
  unsigned char old_ike_initiator_cookie[SSH_ENGINE_IKE_COOKIE_LENGTH];

  /** ESP outbound SPI. */
  SshUInt32 esp_outbound_spi[SSH_ENGINE_TCP_ENCAPS_MAX_SAS];
  /** AH outbound SPI. */
  SshUInt32 ah_outbound_spi[SSH_ENGINE_TCP_ENCAPS_MAX_SAS];

  /** Timestamp of next scheduled timeout for the connection. */
  SshTime timeout_sec;
  SshUInt32 timeout_usec;


} SshEngineTcpEncapsConnStruct;

/* ******************** Visible Function prototypes **************************/

#include "engine_internal.h"
#include "interceptor.h"


/** This function checks if the packet should be processed by the IPsec over
    TCP code and calls TCP decapsulation or handshake handlers. The function
    is called just after flow lookup in fastpath_packet_continue(). This
    function must be called with no locks taken (especially without the
    `flow_control_table_lock').

    Processing of inbound no flow packets:

    - This function performs connection entry lookup and, depending on the
    TCP connection state, passes the packet 'pp' to handshake handling or
    to decapsulation, or lets the packet continue unmodified.

    Processing of outbound noflow packets:

    - This function performs TCP connection lookup for the packet 'pp'
    and triggers a new TCP connection establishment if necessary.

    Note: The function expects that 'pp' is a reassembled packet. */
SshEngineActionRet
ssh_engine_tcp_encaps_process_noflow(SshEngine engine,
                                     SshEnginePacketContext pc,
                                     SshInterceptorPacket pp);

/** This function checks if the packet should be processed by the TCP
    encapsulation code. The function is called after all transform executions
    ssh_engine_execute_transform_step(). This function must be called with no
    locks taken (especially without the `flow_control_table_lock').

    For noflow packets, this function performs connection entry lookup
    based on IKE initiator cookie or ESP spi. For In-flow packets connection
    is fetched from the connection table by connection id.

    If a valid encapsulating TCP connection is found the packet 'pp' is
    passed to TCP encapsulation.

    Function assumes that 'pc' is only partially valid. */
SshEngineActionRet
ssh_engine_tcp_encaps_process_outbound(SshEngine engine,
                                       SshEnginePacketContext pc,
                                       SshInterceptorPacket pp);

/** Bind IKE initiator cookie to a connection entry. Create a new
    connection entry if needed. This should be called when initiating
    IKE negotiation and during IKEv2 IKE SA rekey.

    This creates a new connection entry between endpoints specified by
    arguments `local_addr', `local_port', `peer_addr' and `peer_port',
    and binds `ike_initiator_cookie' to it. The connection entry is
    initialized with CLOSED state. The connection will be opened when
    a trigger packet or incoming syn packet hits the connection entry.

    This calls `callback' with the connection id for the connection or
    SSH_IPSEC_INVALID_INDEX if an error occured. */
void
ssh_engine_pme_tcp_encaps_create_ike_mapping(SshEngine engine,
                                           SshIpAddr local_addr,
                                           SshIpAddr peer_addr,
                                           SshUInt16 local_port,
                                           SshUInt16 peer_port,
                                           unsigned char *ike_initiator_cookie,
                                           SshUInt16 local_ike_port,
                                           SshUInt16 remote_ike_port,
                                           SshPmeIndexCB callback,
                                           void *callback_context);

/** Looks up connection entry between `local_addr' and `peer_addr' that is
    bound to `ike_initiator_cookie'. This calls `callback' with the connection
    id or SSH_IPSEC_INVALID_INDEX if no connection was found. */
void
ssh_engine_pme_tcp_encaps_get_ike_mapping(SshEngine engine,
                                          SshIpAddr local_addr,
                                          SshIpAddr peer_addr,
                                          unsigned char *ike_initiator_cookie,
                                          SshPmeIndexCB callback,
                                          void *callback_context);

/** Updates `new_ike_initiator_cookie' to connection entry IKE mapping for
    connections matching `ike_initiator_cookie', `local_addr' and
    `remote_addr'. If `local_addr' or `remote_addr' are NULL then they are not
    used in matching. If `new_ike_initiator_cookie' is NULL, then this will
    remove the connection entry IKE mapping, and if there are no SPI mappings,
    then also close the connection and free the connection entry. If
    `keep_address_matches' is TRUE, then the connections matching `local_addr',
    `peer_addr' and `ike_initiator_cookie' are ignored and any other
    connections matching `ike_initiator_cookie' are updated. This calls
    `callback' with the connection id of the updated connection entry or
    SSH_IPSEC_INVALID_INDEX if either no connection was found or if the
    connection mapping was removed. */
void
ssh_engine_pme_tcp_encaps_update_ike_mapping(SshEngine engine,
                                       Boolean keep_address_matches,
                                       SshIpAddr local_addr,
                                       SshIpAddr peer_addr,
                                       unsigned char *ike_initiator_cookie,
                                       unsigned char *new_ike_initiator_cookie,
                                       SshPmeIndexCB callback,
                                       void *callback_context);

/** Bind SPIs to the connection entry. This should be called during
    IPSec SA (re-)installation. Returns connection ID.
    This function will grab the 'tcp_encaps_lock'. This function is
    called with 'flow_control_table_lock' taken. */
SshUInt32
ssh_engine_tcp_encaps_create_spi_mapping(SshEngine engine,
                                         SshIpAddr local_addr,
                                         SshIpAddr remote_addr,
                                         unsigned char *ike_initiator_cookie,
                                         SshUInt32 esp_outbound_spi,
                                         SshUInt32 ah_outbound_spi);

/** Removes SPI mappings from the connection entry. If removing the last SPI
    mappings from connection entry, then the connection is closed and removed.
*/
SshUInt32
ssh_engine_tcp_encaps_remove_spi_mapping(SshEngine engine,
                                         SshUInt32 conn_id,
                                         SshUInt32 esp_outbound_spi,
                                         SshUInt32 ah_outbound_spi);

/** Remove all entries from connection and configuration tables and
    cancel all TCP handshake and IKE negotiation timers. */
void
ssh_engine_tcp_encaps_destroy(SshEngine engine);

/** Lookup connection by address and port information extracted from
    a PMTU ICMP message. Consider only established connections, that
    have the IKE negotiation phase completed. Return connection ID
    or SSH_IPSEC_INVALID_INDEX if no matching connection was found. */
SshUInt32
ssh_engine_tcp_encaps_conn_by_pmtu_info(SshEngine engine,
                                        SshIpAddr dst,
                                        SshIpAddr src,
                                        SshUInt16 dst_port,
                                        SshUInt16 src_port);

#endif /* ENGINE_TCP_ENCAPS_H */
#endif /* SSH_IPSEC_TCPENCAP */
