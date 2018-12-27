/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Prototypes and function declarations for the accelerated
   software fastpath.h API.

   @description

   This API provides an interface between the software FastPath and a
   hardware (or accelerated) FastPath. It is intended as an alternative to
   the FastPath API defined in the engine_fastpath.h file. The accelerated
   FastPath API defined here should be used in cases where the FastPath
   replacement is not capable of implementing all of the functionality that
   the software FastPath provides.

   The shared objects between the software and accelerated FastPaths are the
   same flow, transform and next hop objects that are defined in the
   engine_fastpath_types.h file.

   The accelerated Fastpath may call the utility functions defined in
   engine_fastpath_util.h file.

   The following compile-time defines specify what functions the accelerated
   Fastpath implements:

     FASTPATH_PROVIDES_FLOW:
     If defined then the accelerated Fastpath implements allocation and
     handling of the Fastpath flow data types. Otherwise the flow data type
     is internal to the software Fastpath.

     FASTPATH_PROVIDES_LRU_FLOWS:
     If defined then the accelerated Fastpath implements the LRU logic for
     the Fastpath flow data type.

     FASTPATH_PROVIDES_TRD:
     If defined then the accelerated Fastpath implements allocation and
     handling of the Fastpath transform data types. Otherwise the transform
     data type is internal to the software Fastpath.

     FASTPATH_PROVIDES_NH:
     If defined then the accelerated Fastpath implements allocation and
     handling of the Fastpath nexthop data types. Otherwise the nexthop data
     type is internal to the software Fastpath.

     FASTPATH_PROVIDES_SUSPEND:
     If defined then the accelerated fastpath implements suspend and resume
     functionality. Otherwise the software fastpath does never suspend the
     accelerated fastpath.

   The accelerated FastPath implementation must provide the implementation
   of the fastpath_accel_* functions defined below that the software
   Fastpath expects. The accelerated Fastpath implementation may use the
   fastpath_packet_handler() function defined below for passing control of
   packets to the software FastPath or Engine component.

   * Flow, Transform, And Next Hop Data Objects *

   The Fastpath API specifies three data objects that are shared between the
   Engine and FastPath, namely flows, transforms and next hop objects. These
   data types are defined in the engine_fastpath_types.h file. If the
   accelerated FastPath is responsible for allocation of these objects, then
   number of data objects that must be allocated is specified by the
   following compile-time parameters:

   SSH_ENGINE_FLOW_TABLE_SIZE      - FastPath allocates this number of
                                    SshEngineFlowDataStructure objects.

   SSH_ENGINE_TRANSFORM_TABLE_SIZE - FastPath allocates this number of
                                    SshEngineTransformDataStructure objects.

   SSH_ENGINE_NEXT_HOP_HASH_SIZE   - FastPath allocates this number of
                                    SshEngineNextHopDataStructure objects.

   The software Fastpath accesses these objects through a set of functions,
   defined below. The objects are accessed using integer indices which index
   into the table of FastPath allocated objects.

   Note: Accelerated Fastpath is free to allocate storage for the above data
   objects in its own private format (i.e. not identical to the format
   defined in the engine_fastpath_types.h file). The API only specifies that
   that the fastpath_accel_get_* functions return the objects in the format
   expected by the software Fastpath.

   * Accessing FastPath Objects from the software Fastpath *

   FastPath objects are accessed and modified from the software Fastpath
   using a set of functions. The software Fastpath will never access more
   than one FastPath object of a given type (flow, transform or next hop) at
   a time. This means that after a call to one of fastpath_accel_get_*
   functions no other Fastpath data object of the same type will be accessed
   until fastpath_accel_commit_*, fastpath_accel_release_* or
   fastpath_accel_uninit_* is called for the data object. After a a call to
   a fastpath_accel_get_* function, ownership of the returned object is passed
   to the software Fastpath and the software Fastpath is free to modify the
   returned object.

   Note however, that a call to fastpath_accel_get_trd() or
   fastpath_accel_get_nh() may occur after fastpath_accel_get_flow() is
   called but before fastpath_accel_commit_flow() or
   fastpath_accel_release_flow() is called, i.e. the software Fastpath may
   access a next hop or transform object while a flow is being accessed.

   The software Fastpath destroys the Fastpath objects by calling the
   fastpath_accel_uninit_* function. After this no packets are processed
   using that Fastpath object (e.g. a packet should never be matched against
   an uninitialized flow, a valid flow never refers to an uninitialized
   trd). The software Fastpath may access uninitialized Fastpath objects
   with the fastpath_accel_get_* function for retrieving statistics or
   checking object state. Therefore fastpath_accel_uninit_* function MUST
   first commit changes back to the Fastpath and then perform any necessary
   tasks to unitialize the Fastpath object (e.g. remove a flow from flow
   hash table, clear key material from trd object, etc).

   * FastPath Packet Processing Engine *

   Data types: The FastPath API currently uses two data types for passing
   packets between the accelerated FastPath and software Fastpath layers.
   The SshInterceptorPacket type and the SshEnginePacketContext type.

   The SshInterceptorPacket is defined in interceptor/include/interceptor.h
   and is the standard data type used by QuickSec for representing packets.
   The routines in interceptor/include/interceptor.h can be used for
   constructing, freeing, accessing and modifying such packets. The
   accelerated FastPath implementation will need to convert to and from its
   private representation of packets to the SshInterceptorPacket type when
   passing packets between the accelerated FastPath and software Fastpath.

   SshEnginePacketContext is a data type used by the QuickSec software
   Fastpath and Engine for storing auxillary information related to a packet
   while the packet is handled by the software Fastpath. It contains
   information obtained when parsing the packet's headers e.g. IP protocol,
   IP source and destination addresses etc., in addition other information
   such as the packet's flow id are stored in the SshEnginePacketContext
   type. A pointer to the SshInterceptorPacket is also stored in the
   SshEnginePacketContext type, 'pc'.

   The FastPath API functions take as a parameter the data type
   SshEnginePacketContext. This requires that the accelerated Fastpath
   implementation will also need to construct and modify a
   SshEnginePacketContext when calling software Fastpath functions. Utility
   functions are provided in ipsec/quicksec/engine/engine_fastpath_util.h for
   doing this.

   When the software Fastpath passes packets to the accelerated FastPath
   using fastpath_accel_packet_continue(), it passes a
   SshEnginePacketContext type. The accelerated Fastpath implementation
   should only need to access the actual packet, which it may do using the
   engine_fastpath_util.h and interceptor.h APIs.

   The accelerated FastPath implementation must reserve exclusive ranges of
   values for IPv4 identification and IPv6 fragment identification for the
   Engine. These ranges are specified in the defines
   FASTPATH_ENGINE_IP_ID_MIN and FASTPATH_ENGINE_IP_ID_MAX, and
   FASTPATH_ENGINE_IPV6_FRAG_ID_MIN and FASTPATH_ENGINE_IPV6_FRAG_ID_MAX.
*/

#ifndef FASTPATH_ACCEL_H
#define FASTPATH_ACCEL_H 1

#include "ipsec_params.h"
#include "interceptor.h"
#include "engine.h"
#include "engine_fastpath_types.h"

/** Data type for the accelerated FastPath context. */
typedef struct SshFastpathAccelRec *SshFastpathAccel;

/*--------------------------------------------------------------------*/
/* Flow ID computation routine                                        */
/*--------------------------------------------------------------------*/

/** This function computes the flow ID from a packet 'pp' with previous
    tunnel id 'tunnel_id'. The flow id is returned in the 'flow_id' buffer
    which must be of length SSH_ENGINE_FLOW_ID_SIZE. This function should
    use selectors from the packet headers for computing the flow id.
    The input selectors must include the IP addresses from the packet,
    protocol, and port numbers if applicable. For incoming IPsec packets to
    the local host, the SPI must be included in the selectors. The
    selectors may also include other fields such as DSCP selectors. For
    ICMP error messages this should calculate the flow ID from the fields
    of the violating packet found in the payload of the ICMP message. The
    selectors must not include any fields which typically vary for packets
    belonging to a particular flow, e.g. IP length, checksum fields,
    payload data etc.

    This function must ensure that packets matching to different flows
    never result in having the same flow ID.

    The 'tunnel_id' field identifies the tunnel from which this packet
    was decapsulated. If the packet has not been decapsulated from a
    tunnel, 'tunnel_id' is zero. This field must be used as a distinguisher
    in the flow ID computation.

    'pc' contains contains cached information from parsing the packet's
    headers. The implementation should only need to access the flags of
    the 'pc' using the accessor function in engine_fastpath_util.h API
    to detect whether the packet is an IPsec packet directed to the local
    IPsec implementation (the flag SSH_ENGINE_PC_IS_IPSEC).

    Returns FALSE in case of error in which case 'pp' must be freed. */
typedef Boolean (*SshFastpathAccelFlowIDCB)(SshFastpathAccel accel,
                                            SshEnginePacketContext pc,
                                            SshInterceptorPacket pp,
                                            SshUInt32 tunnel_id,
                                            unsigned char *flow_id);


/*--------------------------------------------------------------------*/
/* Packet handler                                                     */
/*--------------------------------------------------------------------*/

/** This function is called whenever the accelerated FastPath wishes to
    pass a packet to the software FastPath. This continues processing of
    the packet in the software FastPath according to `input_state'.

    @param return_state
    The software FastPath will return the packet to the accelerated
    FastPath at the state 'return_state'. If 'return_state' is equal to 0,
    the packet will not be returned to the accelerated FastPath.

    @param pc
    Points to a SshEnginePacketContext containing information for the
    packet.

    This function must not be called with any locks held.

*/
typedef void (*SshFastpathAccelPacketCB)(SshEngine engine,
                                         SshEnginePacketContext pc,
                                         SshEngineActionRet input_state,
                                         SshEngineActionRet return_state);


/*--------------------------------------------------------------------*/
/* Accelerated Fastpath Initialization and Uninitialization           */
/*--------------------------------------------------------------------*/

/** Initialization of the accelerated FastPath. This function is
    guaranteed not to call any functions in Engine.

    @param engine
    Points to the SshEngine object that the accelerated Fastpath must use
    whenever calling the Engine Fastpath Util API functions.

    @param interceptor
    Points to the SshInterceptor object that the accelerated Fastpath must
    use whenever calling the Interceptor API functions.

    @param packet_handler
    Points to the packet handler callback function that the accelerated
    Fastpath must use for passing packets to software Fastpath.

    @param *flow_id_return
    The accelerated Fastpath must fill in this return value parameter with
    a pointer to the flow id calculation routine that the software Fastpath
    uses for flow id calculation.

    @param *fastpath_accel_return
    The accelerated Fastpath must fill in this return value parameter with
    a pointer to the accelerated Fastpath object.

    @return
    If FALSE is returned, the accelerated FastPath is unusable. */
Boolean
fastpath_accel_init(SshEngine engine,
                    SshInterceptor interceptor,
                    SshFastpathAccelPacketCB packet_handler,
                    SshFastpathAccelFlowIDCB *flow_id_return,
                    SshFastpathAccel *fastpath_accel_return);

/** This function can be called to ensure that no more packets will be
    processed in asynchronous processes within the accelerated FastPath.

    @return
    The function returns TRUE if it was succesful, and FALSE if there is
    currently asynchronous processing in effect that cannot be aborted. */
Boolean
fastpath_accel_stop(SshFastpathAccel accel);

/** This function can be called to ensure that no more packets will be
    processed in asynchronous processes within the accelerated FastPath.
    The software fastpath calls this if FASTPATH_PROVIDES_SUSPEND is
    defined. */
void
fastpath_accel_suspend(SshFastpathAccel accel);

/** This function can be called to continue packet processing in
    accelerated fastpath after it has been suspended. The software fastpath
    calls this if FASTPATH_PROVIDES_SUSPEND is defined. */
void
fastpath_accel_resume(SshFastpathAccel accel);

/** This function uninitializes the accelerated fasptath. This function
    cannot be called before fastpath_accel_stop() has successfully
    returned TRUE. */
void
fastpath_accel_uninit(SshFastpathAccel accel);

/** This function is called when the Engine/Policy Manager channel is
    opened. The accelerated FastPath should do any setup that is necessary.
*/
void
fastpath_accel_notify_open(SshFastpathAccel accel);

/** This function is called when the Engine/Policy Manager channel is
    closed. The accelerated FastPath should do any cleanup that is
    necessary. */
void
fastpath_accel_notify_close(SshFastpathAccel accel);

/** This function is used to notify the accelerated FastPath module of
    changes in Engine parameters. */
void
fastpath_accel_set_params(SshFastpathAccel accel,
                          const SshEngineParams params);

/** This function sends the salt used for randomizing the flow id hash
    tables to the accelerated FastPath. This function is deprecated and
    the fastpath implementation is free to ignore the salt. */
void
fastpath_accel_set_salt(SshFastpathAccel accel,
                        const unsigned char *salt,
                        size_t salt_len);


/*--------------------------------------------------------------------*/
/* Accelerated Fastpath object management                             */
/*--------------------------------------------------------------------*/

/** The software fastpath accesses the fastpath objects using the following
    functions. The semantics of the accessor functions follow the semantics
    of the accessor macros in the Engine Fastpath API. */


/** Flow management. These flow management functions map directly to the
    flow accessor macros in engine_fastpath.h. The software Fastpath calls
    these functions if FASTPATH_PROVIDES_FLOW is defined. */


/** This function initializes and returns an SshEngineFlowData object
    with index 'flow_index' in the flow table. 'flow_index' is an integer
    in the range from 0 to SSH_ENGINE_FLOW_TABLE_SIZE - 1. The flow object
    returned by this call must be considered the property of the software
    Fastpath until the changes are committed back using
    fastpath_accel_commit_flow() or the software Fastpath releases the flow
    using fastpath_accel_release_flow(). */
SshEngineFlowData
fastpath_accel_init_flow(SshFastpathAccel accel, SshUInt32 flow_index);

/** This function returns an SshEngineFlowData object with index
    'flow_index' in the flow table. 'flow_index' is an integer in the
    range from 0 to SSH_ENGINE_FLOW_TABLE_SIZE - 1. The flow object
    returned by this call must be considered the property of the software
    Fastpath until the changes are committed back using
    fastpath_accel_commit_flow() or the software Fastpath releases the flow
    using fastpath_accel_release_flow(). */
SshEngineFlowData
fastpath_accel_get_flow(SshFastpathAccel accel, SshUInt32 flow_index);

/** This function is a read-only variant of the above. The software
    Fastpath does not modify a flow which is accessed using this function.
    The accelerated Fastpath may read access the flow, but it may not
    modify it until the software Fastpath has released the flow using the
    fastpath_accel_release_flow(). */
SshEngineFlowData
fastpath_accel_get_read_only_flow(SshFastpathAccel accel,
                                  SshUInt32 flow_index);

/** The fastpath_accel_commit_flow() function is used to propagate back
    changes made to a flow table entry fetched using
    fastpath_accel_get_flow() or fastpath_accel_init_flow(). This is the
    only valid method of updating or setting flow table entries. The
    'flow_index' parameter must be the same as used with the previous
    fastpath_accel_get_flow() or fastpath_accel_init_flow() call, and the
    'flow' parameter  is the value returned by the previous
    fastpath_accel_get_flow() or fastpath_accel_init_flow() call. */
void
fastpath_accel_commit_flow(SshFastpathAccel accel, SshUInt32 flow_index,
                           SshEngineFlowData data);

/** This function signals to the fastpath that the SshEngineFlowData
    structure at 'flow_index' has been destroyed. The accelerated Fastpath
    must update the flow table entry content and then perform any necessary
    task to uninitialize the flow (e.g. related to flow lookup or LRU-based
    caching). 'flow_index' is an integer in the range from 0 to
    SSH_ENGINE_FLOW_TABLE_SIZE - 1. The 'flow_index' parameter must be the
    same as used with a previous fastpath_accel_get_flow() call, and the
    'flow' parameter is the value returned by a previous
    fastpath_accel_get_flow() call. */
void
fastpath_accel_uninit_flow(SshFastpathAccel accel, SshUInt32 flow_index,
                           SshEngineFlowData data);

/** This function is used to return ownership of the flow table entry
    specified by 'flow_index' to the accelerated Fastpath. It must called
    by the software Fastpath when it is finished with the flow entry and no
    changes are being committed back to the accelerated Fastpath. It is
    mandatory to call either fastpath_accel_release_flow(),
    fastpath_accel_commit_flow() or fastpath_accel_uninit_flow() after a
    call to fastpath_accel_get_flow() or fastpath_accel_init_flow() before
    any other Fastpath flow data object can be accessed. It also mandatory
    to call fastpath_accel_release_flow() after a call to
    fastpath_accel_get_read_only_flow() before any other Fastpath flow data
    object can be accesses. The 'flow_index' parameter must be the same as
    used with the corresponding fastpath_accel_get_flow() or
    fastpath_accel_get_read_only_flow() call. */
void
fastpath_accel_release_flow(SshFastpathAccel accel, SshUInt32 flow_index);

/** This function is used to indicate to the accelerated Fastpath that the
    IPsec transform of the flow table entry specified by 'flow_index' has
    been re-keyed. The software fastpath must not have the control of the flow
    when calling this. The transform is found from the flow's
    'forward_transform_index' or 'reverse_transform_index' field. */
void
fastpath_accel_rekey_flow(SshFastpathAccel accel, SshUInt32 flow_index);


/** Transform management. These transform management functions map directly
    to the transform accessor macros in engine_fastpath.h. The software
    Fastpath calls these functions if FASTPATH_PROVIDES_TRD is defined. */


/** This function initializes and returns an SshEngineTransformData object
    with index 'trd_index' in the trd table. The lower 24 bits of
    'trd_index' give the index to the trd table, i.e. are an integer
    in the range from 0 to SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The trd
    object returned by this call must be considered property of the
    software Fastpath until the changes are committed back using
    fastpath_accel_commit_trd() or fastpath_accel_uninit_trd() or the
    software Fastpath releases the trd using fastpath_accel_release_trd().
*/
SshEngineTransformData
fastpath_accel_init_trd(SshFastpathAccel accel, SshUInt32 trd_index);

/** This function returns an SshEngineTransform object with index
    'trd_index' in the trd table. The lower 24 bits of 'trd_index'
    give the index to the transform table, i.e. are an integer in
    the range from 0 to SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The trd
    object returned by this call must be considered property of the
    software Fastpath until the changes are committed back using
    fastpath_accel_commit_trd() or fastpath_accel_uninit_trd() or the
    software Fastpath releases the trd using fastpath_accel_release_trd().
*/
SshEngineTransformData
fastpath_accel_get_trd(SshFastpathAccel accel, SshUInt32 trd_index);

/** This function is a read-only variant of the above. The software
    Fastpath does not modify a trd which is accessed using this function.
    The accelerated Fastpath may read access the trd, but it may not modify
    it until the software Fastpath has released the trd using the
    fastpath_accel_release_trd(). */
SshEngineTransformData
fastpath_accel_get_read_only_trd(SshFastpathAccel accel, SshUInt32 trd_index);

/** This function is used to propagate back changes made to a trd table
    entry fetched using fastpath_accel_get_trd() or
    fastpath_accel_init_trd(). This is the only valid method of updating or
    setting trd table entries. The 'trd_index' parameter must be the same
    as used with the corresponding fastpath_accel_get_trd() or
    fastpath_accel_init_trd() call, and the 'trd' parameter is the value
    returned by the previous fastpath_accel_get_trd() or
    fastpath_accel_init_trd() call. */
void
fastpath_accel_commit_trd(SshFastpathAccel accel, SshUInt32 trd_index,
                          SshEngineTransformData trd);

/** This function signals to the accelerated Fastpath that the
    SshEngineTransformData structure at 'trd_index' has been destroyed. The
    accelerated Fastpath must update the transform table entry content and
    then perform any necessary tasks to uninitialize the transform (e.g.
    related to clearing key material). The lower 24 bits of 'trd_index'
    give the index to the transform table, i.e. are an integer in the range
    from 0 to SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The 'trd_index'
    parameter must be the same as used with a previous
    fastpath_accel_get_trd() call, and the 'trd' parameter is the value
    returned by a previous fastpath_accel_get_trd() call. */
void
fastpath_accel_uninit_trd(SshFastpathAccel accel, SshUInt32 trd_index,
                          SshEngineTransformData trd);

/** This function is used to return ownership of the trd table entry
    specified by 'trd_index' to the accelerated Fastpath. It must called
    by the software Fastpath when it is finished with the trd entry and no
    changes are being committed back to the accelerated Fastpath. It is
    mandatory to call either fastpath_accel_release_trd(),
    fastpath_accel_commit_trd() or fastpath_accel_uninit_trd() after a call
    to fastpath_accel_get_trd() or fastpath_accel_init_trd() before any
    other Fastpath trd data object can be accessed. It is also mandatory to
    call fastpath_accel_release_trd() after a call to
    fastpath_accel_get_read_only_trd() before any other Fastpath trd data
    object can be accessed. The 'trd_index' parameter must be the same as
    used with the corresponding fastpath_accel_get_trd() or
    fastpath_accel_get_read_only_trd() call. */
void
fastpath_accel_release_trd(SshFastpathAccel accel, SshUInt32 trd_index);


/** Nexthop management. These next hop management functions map directly
    to the next hop accessor macros in engine_fastpath.h. The software
    Fastpath calls these functions if FASTPATH_PROVIDES_NH is defined. */


/** This function initializes and returns an SshEngineNextHopData object
    with index 'nh_index' in the next hop table. 'nh_index' is an integer
    in the range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1. The returned
    next hop must be considered property of the software Fastpath until the
    changes are committed back using fastpath_accel_commit_nh() or the
    software Fastpath releases the next hop using
    fastpath_accel_release_nh(). */
SshEngineNextHopData
fastpath_accel_init_nh(SshFastpathAccel accel, SshUInt32 nh_index);

/** This function returns an SshEngineNextHop object with index
    'nh_index' in the nh table. 'nh_index' is an integer in the
    range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1. The next hop object
    returned by this call must be considered property of the software
    Fastpath until the changes are committed back using
    fastpath_accel_commit_nh() or the next hop is released using
    fastpath_accel_release_nh(). */
SshEngineNextHopData
fastpath_accel_get_nh(SshFastpathAccel accel, SshUInt32 nh_index);

/** This function is a read-only variant of the above. The software
    Fastpath does not modify a nexthop which is accessed using this
    function. The accelerated Fastpath may read access the next hop, but it
    may not modify it until the software Fastpath has released the next hop
    using the fastpath_accel_release_nh(). */
SshEngineNextHopData
fastpath_accel_get_read_only_nh(SshFastpathAccel accel, SshUInt32 nh_index);

/** This function is used to propagate back changes made to a next hop
    table entry fetched using fastpath_accel_get_nh() or
    fastpath_accel_init_nh(). This is the only valid method of updating or
    setting next hop table entries. The 'nh_index' parameter must be the
    same as used with the previous fastpath_accel_get_nh() or
    fastpath_accel_init_nh() call, and the 'nh' parameter is the value
    returned by the previous fastpath_accel_get_nh() or
    fastpath_accel_init_nh() call. */
void
fastpath_accel_commit_nh(SshFastpathAccel accel, SshUInt32 nh_index,
                         SshEngineNextHopData nh);

/** This function signals to the accelerated Fastpath that the
    SshEngineNextHopData structure at 'nh_index' has been destroyed. The
    accelerated Fastpath must update the nexthop table entry content and
    then perform any necessary tasks to unitialize the nexthop. 'nh_index'
    is an integer in the range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1.
    The 'nh_index' parameter must be the same as used with a previous
    fastpath_accel_get_nh() call, and the 'nh' parameter is the value
    returned by a previous fastpath_accel_get_nh() call. */
void
fastpath_accel_uninit_nh(SshFastpathAccel accel, SshUInt32 nh_index,
                         SshEngineNextHopData nh);

/** This function is used to return ownership of the next hop table entry
    specified by 'nh_index' to the accelerated Fastpath. It must called by
    the software Fastpath when it is finished with the next hop entry and
    no changes are being committed back to the fastpath. It is mandatory to
    call either fastpath_accel_release_nh() or fastpath_accel_commit_nh()
    after a call to fastpath_accel_get_nh() or fastpath_accel_init_nh()
    before any other Fastpath next hop data object can be accessed. It is
    also mandatory to call fastpath_accel_release_nh() after a call to
    fastpath_accel_get_read_only_nh() before any other Fastpath next hop
    data object can be accessed. The 'nh_index' parameter must be the same
    as used with the corresponding fastpath_accel_get_nh() or
    fastpath_accel_get_read_only_nh() call. */
void
fastpath_accel_release_nh(SshFastpathAccel accel, SshUInt32 nh_index);

/*--------------------------------------------------------------------*/
/* Flow lru management                                                */
/*--------------------------------------------------------------------*/


/** The software Fastpath calls these functions if
    FASTPATH_PROVIDES_LRU_FLOWS is defined. */


/** This function is called by the software Fastpath when it is required
    that an existing flow be reaped to allow for the creation of a new
    flow.

    @return
    This function returns the least recently used flow (of the active
    flows) in the FastPath that has an lru_level of at most 'lru_level' and
    does not have the SSH_ENGINE_FLOW_D_NO_LRU_REAP flag set. */
SshUInt32
fastpath_accel_get_lru_flow(SshFastpathAccel accel, SshUInt32 lru_level);

/** This function is called by the software FastPath whenever it processes
    a packet using the flow with flow index equal to 'flow_index'.

    The purpose is to indicate to the accelerated FastPath that the
    flow has been recently used. The accelerated FastPath should
    use this information when internally managing it's flow LRU data
    structures. */
void
fastpath_accel_bump_lru_flow(SshFastpathAccel accel, SshUInt32 flow_index);


/*--------------------------------------------------------------------*/
/* Flow lookup                                                        */
/*--------------------------------------------------------------------*/

/** This function is called by the software FastPath to lookup a flow for
    the packet context 'pc'. The flow id of the packet and the actual
    packet pp are retrieved from 'pc' using the engine_fastpath_util.h
    API. This function may need set the flow index, flags and flow id in
    'pc'. This should be done using the above mentioned API.

    On success the should return the flow as if the fastpath accessed it
    with fastpath_accel_get_flow(). The software FastPath will call either
    fastpath_accel_commit_flow() or fastpath_accel_release_flow() for the
    returned flow when it finishes processing the flow.

    If this is an IPsec packet directed to local IPsec implementation then
    the flag SSH_ENGINE_PC_IS_IPSEC is set in 'pc'. If no matching flow is
    found then this function must clear the flag SSH_ENGINE_PC_IS_IPSEC in
    'pc', recalculate and update flow id in 'pc' and redo the flow lookup.

    @return
    If no flow is found this function should return NULL.

    If a matching flow is found, flow index in 'pc' must be set to the
    index of the matching flow. If the packet matches a flow in the forward
    direction, this function must set the SSH_ENGINE_PC_FORWARD flag in
    'pc'. The matching flow must be returned by this function.

    If a fatal error occurs this function must free the packet, set pp in
    `pc' to NULL and return NULL. */
SshEngineFlowData
fastpath_accel_lookup_flow(SshFastpathAccel accel,
                           SshEnginePacketContext pc);


/*--------------------------------------------------------------------*/
/* FastPath Packet Processing                                         */
/*--------------------------------------------------------------------*/

/** This function passes a packet from the software FastPath to the
    accelerated FastPath for processing. This continues processing of
    the packet according to `ret'.

    This function must eventually free pp in `pc' (by sending or freeing
    it), must update counters, and must free `pc'.

    This function must not be called with any locks held.

    @param pc
    Points to a SshEnginePacketContext containing information for the
    packet.
*/
void
fastpath_accel_packet_continue(SshFastpathAccel accel,
                               SshEnginePacketContext pc,
                               SshEngineActionRet ret);


#ifdef SSH_IPSEC_STATISTICS
/*--------------------------------------------------------------------*/
/* Querying statistics information from the accelerated Fastpath      */
/*--------------------------------------------------------------------*/

/** Callback function for returning global statistics.  `stats' is the
    statistics, or NULL on failure.  The callback must copy `stats' if they
    are needed after this call. */
typedef void
(*SshFastpathAccelGlobalStatsCB)(SshEngine engine,
                                 const SshFastpathGlobalStats stats,
                                 void *context);

/** Retrieves global statistics information from the fastpath. `callback' will
    be called with `context' and `stats' either during this call or later; if
    the statistics could not be retrieved, then `stats' will be NULL.  The
    callback should copy the statistics if they are needed after the call. */
void fastpath_accel_get_global_stats(SshFastpathAccel accel,
                                     SshFastpathAccelGlobalStatsCB callback,
                                     void *context);

#endif /* SSH_IPSEC_STATISTICS */

#endif /* FASTPATH_ACCEL_H */
