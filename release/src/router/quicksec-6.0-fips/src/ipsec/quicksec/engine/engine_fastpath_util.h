/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Prototypes and function declarations for the engine_fastpath API.

   <keywords FastPath/prototypes, FastPath/function declarations>

   @description
   This file contains the declarations of utility functions that the Engine
   implements.
*/

#ifndef ENGINE_FASTPATH_UTIL_H
#define ENGINE_FASTPATH_UTIL_H 1

#include "ipsec_params.h"
#include "engine_fastpath_types.h"
#include "interceptor.h"
#include "engine.h"


/*--------------------------------------------------------------------*/
/* Utility functions for handling packet contexts                     */
/*--------------------------------------------------------------------*/

/** Allocate a packet context.

    @return
    Returns NULL if no packets are available.

    */
SshEnginePacketContext ssh_engine_alloc_pc(SshEngine engine);

/** Initialize the packet context for starting the processing of a new
    packet. In addition this function pulls up the packet headers in
    'pp' and stores relevant information to the packet context 'pc'.

    If the packet 'pp' has been decapsulated from a tunnel, the
    parameters 'tunnel_id' and 'prev_transform_index' specify the
    previous tunnel. These fields are required since the policy
    decision for a packet differs according to whether that packet was
    decapsulated from a tunnel or not, and so the previous tunnel ID
    is a required input to the flow ID computation.

    @param pc
    Packet context.

    @param engine
    Engine.

    @param pp
    The Interceptor packet for which the packet context 'pc' is
    allocated for.

    @param tunnel_id
    Tunnel ID. Should be set to the 'inbound_tunnel_id' field of the
    transform object used for decapsulating the packet
    (d_trd->inbound_tunnel_id). If 'pp' has not been decapsulated from
    a tunnel, 'tunnel_id' should be zero.

    @param prev_transform_index
    The previous transformation index. Should be set to the transform
    index of the IPsec flow used for decapsulating the packet
    (flow->transform_index). If 'pp' has not been decapsulated from a
    tunnel, 'prev_transform_index' should be SSH_IPSEC_INVALID_INDEX.

    @return
    Returns FALSE if an error occurred, in which case 'pp' is already
    freed.

    */
Boolean
ssh_engine_init_and_pullup_pc(SshEnginePacketContext pc,
                              SshEngine engine,
                              SshInterceptorPacket pp,
                              SshUInt32 tunnel_id,
                              SshUInt32 prev_transform_index);

/** Free the packet context 'pc'. This function must eventually
    be called after a successful call to ssh_engine_alloc_pc(). This does not
    free 'pc->pp', which must be consumed or freed separately. */
void
ssh_engine_free_pc(SshEngine engine, SshEnginePacketContext pc);

/** This accessor function sets 'pp' in 'pc'. */
void
ssh_engine_pc_set_pp(SshEnginePacketContext pc, SshInterceptorPacket pp);

/** This accessor function sets 'flags' in 'pc'. */
void
ssh_engine_pc_set_flags(SshEnginePacketContext pc, SshUInt32 flags);

/** This accessor function sets 'flow_index' in 'pc'. */
void
ssh_engine_pc_set_flow_index(SshEnginePacketContext pc, SshUInt32 flow_index);

/** This accessor function sets audit information in 'pc'.
    This is used for filling in the audit information before
    passing 'pc' to ssh_engine_audit_packet_context().

    @param pc
    Packet context.

    @param corruption
    Specifies the how the packet is corrupted.

    @param ip_option
    Specifies the type of corrupted IPv4 header option or the type of
    corrupted IPv6 extension header. This parameter should be set to
    zero if it is not applicable.

    @param flowlabel
    Specifies the flow label of a corrupted IPv6 packet.
    This parameter should be set to zero if it is not applicable.

    @param spi
    Specifies the SPI value of a corrupted IPsec packet.
    This parameter should be set to zero if it is not applicable.

    @param seq
    Specifies the sequence number of a corrupted IPsec packet.
    This parameter should be set to zero if it is not applicable.

    */
void
ssh_engine_pc_set_audit_info(SshEnginePacketContext pc,
                             SshEnginePacketCorruption corruption,
                             SshUInt32 ip_option,
                             SshUInt32 flowlabel,
                             SshUInt32 spi,
                             SshUInt32 seq);

/** This accessor function returns a pointer to 'pp' in 'pc'. */
SshInterceptorPacket
ssh_engine_pc_get_pp(SshEnginePacketContext pc);

/** This accessor function returns 'flags' in 'pc'. */
SshUInt32
ssh_engine_pc_get_flags(SshEnginePacketContext pc);

/** This accessor function returns 'tunnel_id' in 'pc'. */
SshUInt32
ssh_engine_pc_get_tunnel_id(SshEnginePacketContext pc);

/** This accessor function returns 'prev_transform_index' in 'pc'. */
SshUInt32
ssh_engine_pc_get_prev_transform_index(SshEnginePacketContext pc);

/** This accessor function returns a pointer to 'flow_id' in 'pc'. */
unsigned char *
ssh_engine_pc_get_flow_id(SshEnginePacketContext pc);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/** This accessor function returns the length of the media header that the
    software FastPath has added to the packet 'pc'. */
size_t
ssh_engine_pc_get_media_header_length(SshEnginePacketContext pc);
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/*--------------------------------------------------------------------*/
/* Utility functions for handling packets                             */
/*--------------------------------------------------------------------*/

/** This is a utility function that may be used by the FastPath
    implementation to ease the computation of flow ID's for packets
    corresponding to ICMP error messages whose data payload contains a partial
    inner packet. For such packets the flow ID should be computed from the
    inner packet, namely the ICMP packet should be matched to the flow
    for which the error message was triggered.

    This function allocates and constructs a partial packet corresponding
    to the inner packet which generated the ICMP error message, the
    packet corresponding to the ICMP error message is in 'pp'. This function
    fails if 'pp' is not an ICMP error message.

    Note that the constructed partial packet contains incomplete protocol
    headers. Only the address and port information is filled in. It is not
    guaranteed that the constructed packet will pass the sanity checks
    that are normally performed for packets received from network.

    @param engine
    Engine.

    @param pp
    The packet corresponding to the ICMP error message.

    @return
    On success this returns the newly allocated inner packet. On failure
    this frees 'pp' and returns NULL. */
SshInterceptorPacket
ssh_engine_icmp_get_inner_packet(SshEngine engine, SshInterceptorPacket pp);


/*--------------------------------------------------------------------*/
/* FastPath-To-Engine                                                 */
/*--------------------------------------------------------------------*/

/*  All of the FastPath-to-Engine functions must be called without
    any FastPath lock held. */

/** Log an audit event which this packet has generated. The auditing
    state is retrieved from 'audit' structure of 'pc', which must be filled
    in before calling this. The violating packet must be in 'pp' of 'pc'.

    This function consumes both 'pc' and 'pp' in 'pc'. */
void
ssh_engine_audit_packet_context(SshEngine engine,
                                SshEnginePacketContext pc);

/** This function initiates an asynchronous send of an ICMP error
    packet to the originator of the packet.  The send is asynchronous
    in the case that the packet 'pp' in 'pc' has the SSH_PACKET_FROMPROTOCOL
    flag set, in which case the source address for the reply is fetched
    using ssh_engine_route().

    This function takes care of routing the packet appropriately, so
    that it gets sent out from the correct interface and possibly gets
    tunneled using the appropriate tunnel. The sent ICMPs will be
    rate-limited so that the same ICMP will not be sent more than
    about once per second, and that the total number of ICMPs sent per
    second is limited.  This will also check for broadcast addresses,
    and will not send ICMPs to such addresses.

    The function steals the packet 'pp' in 'pc' which is assumed to be the
    offending packet. This does not free 'pc'. */
void
ssh_engine_send_icmp_error(SshEngine engine,
                           SshEnginePacketContext pc,
                           SshUInt8 type, SshUInt8 code,
                           SshUInt32 extra);

/** Send a TCP RST packet to the originator of the packet. The send
    is asynchronous in the case that the packet 'pp' in 'pc' has the
    SSH_PACKET_FROMPROTOCOL flag set, in which case the source address
    for the reply is fetched using ssh_engine_route().

    This will take care of routing the packet appropriately, so that
    it gets sent out from the correct interface and possibly gets
    tunneled using the appropriate tunnel. The sent TCP RST's will be
    rate-limited so that the same TCP RST will not be sent more than
    about once per second, and that the total number of TCP RST's sent
    per second is limited. This will also check for broadcast
    addresses, and will not send TCP RST to such addresses.

    On failure this frees and clears 'pp' in 'pc'. This does not free 'pc'. */
void
ssh_engine_send_tcp_rst(SshEngine engine, SshEnginePacketContext pc);

/** Schedule control plane timeout for flow processing to be run
    in near future (in about engine->age_timeout_interval
    microseconds or sooner).

    On configurations without periodic Engine timeout the FastPath
    implementation should call this function when the hardware has
    processed packets. Under constant traffic load this should get
    called roughly at least once per engine->age_timeout_interval.

    On configurations with periodic Engine timeout, the FastPath
    implementation does not need to call this function. */
void
ssh_engine_age_timeout_schedule(SshEngine engine);

#endif /* ENGINE_FASTPATH_UTIL_H */
