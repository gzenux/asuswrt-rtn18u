/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Prototypes and function declarations for the engine_fastpath API.

   <keywords FastPath/prototypes, FastPath/function declarations>

   @description

   * Flow, Transform, And Next Hop Data Objects *

   The FastPath API specifies three data objects that are shared
   between the Engine and FastPath, namely flows, transforms and next
   hop objects. These data types are defined in the
   engine_fastpath_types.h file. FastPath is responsible for
   allocation of these objects. The number of data objects that must be
   allocated is specified by the following compile-time parameters:

   SSH_ENGINE_FLOW_TABLE_SIZE      - FastPath allocates this number of
                                    SshEngineFlowDataStructure objects.

   SSH_ENGINE_TRANSFORM_TABLE_SIZE - FastPath allocates this number of
                                    SshEngineTransformDataStructure objects.

   SSH_ENGINE_NEXT_HOP_HASH_SIZE   - FastPath allocates this number of
                                    SshEngineNextHopDataStructure objects.

   The Engine accesses these objects through a set of macros, defined
   below, that the FastPath implementation must provide to the Engine.
   The objects are accessed using integer indices which index into the
   table of FastPath allocated objects.

   Note: FastPath is free to allocate storage for the above data
   objects in its own private format (i.e. not identical to the format
   defined in the engine_fastpath_types.h file). The API only specifies
   that that the FASTPATH_GET_* macros return the objects in the format
   expected by the Engine.


   * Accessing FastPath Objects from the Engine *

   FastPath objects are accessed and modified from the Engine using a
   set of macros. The Engine will never access more than one FastPath
   object of a given type (flow, transform or next hop) at a time. This
   means that after a call to one of FASTPATH_GET_* macros no other
   FastPath data object of the same type will be accessed until
   FASTPATH_COMMIT_*, FASTPATH_RELEASE_* or FASTPATH_UNINIT_* is called
   for the data object. After a a call to a FASTPATH_GET_* macro, ownership
   of the return object is passed to the Engine and the Engine is free to
   modify the returned object.

   Note however, that a call to FASTPATH_GET_TRD or FASTPATH_GET_NH
   may occur after FASTPATH_GET_FLOW is called but before
   FASTPATH_{COMMIT,RELEASE}_FLOW is called, i.e. the Engine may
   access a next hop or transform object while a flow is being
   accessed.

   The Engine destroys the FastPath objects by calling the FASTPATH_UNINIT_*
   macro. After this no packets are processed using that FastPath object
   (e.g. a packet should never be matched against an uninitialized flow,
   a valid flow never refers to an uninitialized trd). The Engine may access
   uninitialized FastPath objects with the FASTPATH_GET_* macro for retrieving
   statistics. Therefore FASTPATH_UNINIT_* macros MUST first commit changes
   back to the FastPath and then perform any necessary tasks to unitialize
   the FastPath object (e.g. remove a flow from flow hash table, clear key
   material from trd object, etc).

   * FastPath Packet Processing Engine *

   Data types: The FastPath API currently uses two data types for
   passing packets between the FastPath and Engine layers. The
   SshInterceptorPacket type and the SshEnginePacketContext type.

   The SshInterceptorPacket is defined in the
   interceptor/include/interceptor.h file and is the standard data type
   used by QuickSec for representing packets.  The routines in
   ipsec/engine-interface/interceptor.h can be used for constructing,
   freeing, accessing and modifying such packets. The FastPath
   implementation will need to convert to and from its private
   representation of packets to the SshInterceptorPacket type when
   passing packets between the FastPath and Engine.

   SshEnginePacketContext is a data type used by the QuickSec
   Engine for storing auxillary information related to a packet while
   the packet is handled by the Engine. It contains information
   obtained when parsing the packet's headers e.g. IP protocol, IP
   source and destination addresses etc., in addition other information
   such as the packet's flow id are stored in the
   SshEnginePacketContext type. A pointer to the SshInterceptorPacket,
   'pc->pp', is also stored in the SshEnginePacketContext type, 'pc'.

   The FastPath API functions take as a parameter the data type
   SshEnginePacketContext. This requires that the FastPath
   implementation will also need to construct a SshEnginePacketContext
   when calling Engine functions. Utility functions are provided below
   for doing this.

   When the Engine passes packets to the FastPath using
   fastpath_packet_continue(), it passes a SshEnginePacketContext type.
   The FastPath implementation should only need to access the actual
   packet 'pc->pp', which it may do using the interceptor.h API and
   should not need to access any other fields in 'pc'.

   The FastPath implementation must reserve exclusive ranges of values
   for IPv4 identification and IPv6 fragment identification for the
   Engine. These ranges are specified in the defines FASTPATH_ENGINE_IP_ID_MIN
   and FASTPATH_ENGINE_IP_ID_MAX, and FASTPATH_ENGINE_IPV6_FRAG_ID_MIN
   and FASTPATH_ENGINE_IPV6_FRAG_ID_MAX.
*/

#ifndef ENGINE_FASTPATH_H
#define ENGINE_FASTPATH_H 1

#include "ipsec_params.h"
#include "engine_fastpath_types.h"


/** Data type for the FastPath context. */
typedef struct SshFastpathRec *SshFastpath;


/*--------------------------------------------------------------------*/
/* Accessing FastPath flows from the Engine                           */
/*--------------------------------------------------------------------*/


/** Initialize and return an SshEngineFlowData object with index 'flow_index'
    in the flow table.

    The flow object returned by this call must be considered the
    property of the Engine until the changes are committed back using
    FASTPATH_COMMIT_FLOW() or the Engine releases the flow using
    FASTPATH_RELEASE_FLOW().

    @param flow_index
    An integer in the range from 0 to SSH_ENGINE_FLOW_TABLE_SIZE - 1.

    #define FASTPATH_INIT_FLOW(fastpath, flow_index)
*/

/** Return an SshEngineFlowData object with index 'flow_index' in
    the flow table.

    The flow object returned by this call must be considered the
    property of the Engine until any changes are committed back using
    FASTPATH_COMMIT_FLOW() or FASTPATH_UNINIT_FLOW() or the flow is
    released using FASTPATH_RELEASE_FLOW().

    @param flow_index
    An integer in the range from 0 to SSH_ENGINE_FLOW_TABLE_SIZE - 1.

    #define FASTPATH_GET_FLOW(fastpath, flow_index)
*/

/** A read-only variant of FASTPATH_GET_FLOW. The Engine does not
    modify a flow which is accessed using this macro. The FastPath
    may read access the flow, but it may not modify it until the Engine
    has released the flow using the FASTPATH_RELEASE_FLOW().

    #define FASTPATH_GET_READ_ONLY_FLOW(fastpath, flow_index)
*/

/** The FASTPATH_COMMIT_FLOW() macro is used to propagate back changes
    made to a flow table entry fetched using FASTPATH_GET_FLOW() or
    FASTPATH_INIT_FLOW(). This is the only valid method of updating or
    setting flow table entries. The 'flow_index' parameter must be the same
    as used with the previous FASTPATH_GET_FLOW() or FASTPATH_INIT_FLOW()
    call, and the 'flow' parameter  is the value returned by the previous
    FASTPATH_GET_FLOW() or FASTPATH_INIT_FLOW() call.

    #define FASTPATH_COMMIT_FLOW(fastpath, flow_index, flow)
*/

/** This macro signals to the FastPath that the SshEngineFlowData
    structure at 'flow_index' has been destroyed. The FastPath must update
    the flow table entry content and then perform any necessary task to
    uninitialize the flow (e.g. related to flow lookup or LRU-based caching).
    'flow_index' is an integer in the range from 0 to
    SSH_ENGINE_FLOW_TABLE_SIZE - 1. The 'flow_index' parameter must be the
    same as used with a previous FASTPATH_GET_FLOW() call, and the 'flow'
    parameter is the value returned by a previous FASTPATH_GET_FLOW() call.

    #define FASTPATH_UNINIT_FLOW(fastpath, flow_index, flow)
*/

/** The FASTPATH_RELEASE_FLOW() macro is used to return ownership of the
    flow table entry specified by 'flow_index' to the FastPath. It must
    called by the Engine when it is finished with the flow entry and no
    changes are being committed back to the FastPath. It is mandatory to
    call either FASTPATH_RELEASE_FLOW(), FASTPATH_COMMIT_FLOW() or
    FASTPATH_UNINIT_FLOW() after a call to FASTPATH_GET_FLOW() or
    FASTPATH_INIT_FLOW() before any other fastpath  flow data object can be
    accessed. It also mandatory to call FASTPATH_RELEASE_FLOW() after a call
    to FASTPATH_GET_READ_ONLY_FLOW() before any other fastpath flow data
    object can be accesses. The 'flow_index' parameter must be the same as
    used with the corresponding FASTPATH_GET_FLOW() or
    FASTPATH_GET_READ_ONLY_FLOW() call.

    #define FASTPATH_RELEASE_FLOW(fastpath, flow_index)
*/

/** The FASTPATH_REKEY_FLOW() macro is used to indicate to the fastpath that
    the IPsec transform of the flow table entry specified by 'flow_index' has
    been re-keyed. The Engine must not have the control of the flow when
    calling this. The transform is found from the flow's
    'forward_transform_index' or 'reverse_transform_index' field.

    #define FASTPATH_REKEY_FLOW(fastpath, flow_index)
*/


/*--------------------------------------------------------------------*/
/* Accessing FastPath transforms from the Engine                      */
/*--------------------------------------------------------------------*/


/** This function initializes and returns an SshEngineTransformData object
    with index 'trd_index' in the trd table. The lower 24 bits of
    'trd_index' give the index to the trd table, i.e. are an integer
    in the range from 0 to SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The trd
    object returned by this call must be considered property of the Engine
    until the changes are committed back using FASTPATH_COMMIT_TRD() or
    FASTPATH_UNINIT_TRD() or the Engine releases the trd using
    FASTPATH_RELEASE_TRD().

    #define FASTPATH_INIT_TRD(fastpath, trd_index)
*/

/** This function returns an SshEngineTransform object with index
    'trd_index' in the trd table. The lower 24 bits of 'trd_index'
    give the index to the transform table, i.e. are an integer in
    the range from 0 to SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The trd
    object returned by this call must be considered property of the Engine
    until the changes are committed back using FASTPATH_COMMIT_TRD() or
    FASTPATH_UNINIT_TRD() or the Engine releases the trd using
    FASTPATH_RELEASE_TRD().

    #define FASTPATH_GET_TRD(fastpath, trd_index)
*/

/** This function is a read-only variant of the above. The Engine does
    not modify a trd which is accessed using this macro. The FastPath
    may read access the trd, but it may not modify it until the Engine
    has released the trd using the FASTPATH_RELEASE_TRD().

    #define FASTPATH_GET_READ_ONLY_TRD(fastpath, trd_index)
*/

/** The FASTPATH_COMMIT_TRD() macro is used to propagate back changes
    made to a trd table entry fetched using FASTPATH_GET_TRD() or
    FASTPATH_INIT_TRD(). This is the only valid method of updating or
    setting trd table entries. The 'trd_index' parameter must be the same
    as used with the corresponding FASTPATH_GET_TRD() or FASTPATH_INIT_TRD()
    call, and the 'trd' parameter is the value returned by the previous
    FASTPATH_GET_TRD() or FASTPATH_INIT_TRD() call.

    #define FASTPATH_COMMIT_TRD(fastpath, trd_index, trd)
*/

/** This macro signals to the FastPath that the SshEngineTransformData
    structure at 'trd_index' has been destroyed. The FastPath must update
    the transform table entry content and then perform any necessary tasks
    to uninitialize the transform (e.g. related to clearing key material).
    The lower 24 bits of 'trd_index' give the index to the transform table,
    i.e. are an integer in the range from 0 to
    SSH_ENGINE_TRANSFORM_TABLE_SIZE - 1. The 'trd_index' parameter must be
    the same as used with a previous FASTPATH_GET_TRD() call, and the 'trd'
    parameter is the value returned by a previous FASTPATH_GET_TRD() call.

    #define FASTPATH_UNINIT_TRD(fastpath, trd_index, trd)
*/

/** The FASTPATH_RELEASE_TRD() macro is used to return ownership of the
    trd table entry specified by 'trd_index' to the FastPath. It must called
    by the Engine when it is finished with the trd entry and no changes are
    being committed back to the FastPath. It is mandatory to call either
    FASTPATH_RELEASE_TRD(), FASTPATH_COMMIT_TRD() or FASTPATH_UNINIT_TRD()
    after a call to FASTPATH_GET_TRD() or FASTPATH_INIT_TRD() before any other
    FastPath TRD data object can be accessed. It is also mandatory to call
    FASTPATH_RELEASE_TRD() after a call to FASTPATH_GET_READ_ONLY_TRD()
    before any other FastPath TRD data object can be accessed. The
    'trd_index' parameter must be the same as used with the corresponding
    FASTPATH_GET_TRD() or FASTPATH_GET_READ_ONLY_TRD() call.

    #define FASTPATH_RELEASE_TRD(fastpath, trd_index)
*/


/*--------------------------------------------------------------------*/
/* Accessing FastPath next hops objects from the Engine               */
/*--------------------------------------------------------------------*/


/** This function initializes and returns an SshEngineNextHopData object
    with index 'nh_index' in the next hop table. 'nh_index' is an integer
    in the range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1. The returned
    next hop must be considered property of the Engine until the changes
    are committed back using FASTPATH_COMMIT_NH() or the Engine releases
    the next hop using FASTPATH_RELEASE_NH().

    #define FASTPATH_INIT_NH(fastpath, nh_index)
*/

/** This function returns an SshEngineNextHop object with index
    'nh_index' in the nh table. 'nh_index' is an integer in the
    range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1. The next hop object
    returned by this call must be considered property of the Engine until
    the changes are committed back using FASTPATH_COMMIT_NH() or the next
    hop is released using FASTPATH_RELEASE_NH().

    #define FASTPATH_GET_NH(fastpath, nh_index)
*/

/** This function is a read-only variant of the above. The Engine does
    not modify a nexthop which is accessed using this macro. The FastPath
    may read access the next hop, but it may not modify it until the Engine
    has released the next hop using the FASTPATH_RELEASE_NH().

    #define FASTPATH_GET_READ_ONLY_NH(fastpath, nh_index)
*/

/** The FASTPATH_COMMIT_NH() macro is used to propagate back changes
    made to a next hop table entry fetched using FASTPATH_GET_NH() or
    FASTPATH_INIT_NH(). This is the only valid method of updating or
    setting next hop table entries. The 'nh_index' parameter must be the
    same as used with the previous FASTPATH_GET_NH() or FASTPATH_INIT_NH()
    call, and the 'nh' parameter is the value returned by the previous
    FASTPATH_GET_NH() or FASTPATH_INIT_NH() call.

    #define FASTPATH_COMMIT_NH(fastpath, nh_index, nh)
*/

/** This macro signals to the FastPath that the SshEngineNextHopData
    structure at 'nh_index' has been destroyed. The FastPath must update
    the nexthop table entry content and then perform any necessary tasks to
    unitialize the nexthop.

    @param nh_index
    An integer in the range from 0 to SSH_ENGINE_NEXT_HOP_HASH_SIZE - 1.
    The 'nh_index' parameter must be the same as used with a
    previous FASTPATH_GET_NH() call.

    @param nh
    The value returned by a previous FASTPATH_GET_NH() call.

    #define FASTPATH_UNINIT_NH(fastpath, nh_index, nh)
*/

/** The FASTPATH_RELEASE_NH() macro is used to return ownership of the
    next hop table entry specified by 'nh_index' to the FastPath. It must
    called by the Engine when it is finished with the next hop entry and no
    changes are being committed back to the FastPath. It is mandatory to call
    either FASTPATH_RELEASE_NH() or FASTPATH_COMMIT_NH() after a call to
    FASTPATH_GET_NH() or FASTPATH_INIT_NH() before any other FastPath next
    hop data object can be accessed. It is also mandatory to call
    FASTPATH_RELEASE_NH() after a call to FASTPATH_GET_READ_ONLY_NH() before
    any other FastPath next hop data object can be accessed. The 'nh_index'
    parameter must be the same as used with the corresponding
    FASTPATH_GET_NH() or FASTPATH_GET_READ_ONLY_NH() call.

    #define FASTPATH_RELEASE_NH(fastpath, nh_index)
*/


/*--------------------------------------------------------------------*/
/* Flow ID computation routine                                        */
/*--------------------------------------------------------------------*/


/** This function computes the flow ID from a packet 'pp' with previous
    tunnel id 'tunnel_id'. The flow id is returned in the 'flow_id' buffer
    which must be of length SSH_ENGINE_FLOW_ID_SIZE. This function should
    use selectors from the packet headers for computing the flow id.
    The input selectors must include the IP addresses from the packet,
    protocol, and port numbers if applicable. For incoming IPsec packets to
    the local host, the SPI must be included in the selectors. The selectors
    may also include other fields such as DSCP selectors. The selectors
    must not include any fields which typically vary for packets belonging to
    a particular flow, e.g. IP length, checksum fields, payload data etc.

    This function must ensure that packets matching to different flows
    never result in having the same flow ID.

    The tunnel_id field identifies the tunnel from which this packet
    was decapsulated. If the packet has not been decapsulated from a tunnel,
    tunnel_id is zero. This field must be used as a distinguisher in the
    flow ID computation.

    'pc' contains contains cached information from parsing the packet's
    headers. Implementations should not make use of this field as this type
    is internal to the Engine and its contents are likely to be modified.
    This field should only be used by the software FastPath implementation.

    Returns FALSE in case of error in which case 'pp' must be freed. */
typedef Boolean (*SshFastpathFlowIDCB)(SshFastpath fastpath,
                                       SshEnginePacketContext pc,
                                       SshInterceptorPacket pp,
                                       SshUInt32 tunnel_id,
                                       unsigned char *flow_id);


/*--------------------------------------------------------------------*/
/* Packet handler                                                     */
/*--------------------------------------------------------------------*/

/** This function is called whenever the FastPath wishes to pass a packet
    to the Engine.

    @param pc
    Points to a SshEnginePacketContext containing information for the
    packet.

    This function must not be called with any locks held.

*/
typedef void (*SshFastpathPacketCB)(SshEngine engine,
                                    SshEnginePacketContext pc);


/*--------------------------------------------------------------------*/
/* FastPath Initialization and Uninitialization                       */
/*--------------------------------------------------------------------*/


/** Initialization of the FastPath. This function is guaranteed not to
    call any functions in the Engine.

    @param engine
    Points to the SshEngine object that the FastPath must use whenever
    calling the Engine FastPath Util API functions.

    @param interceptor
    Points to the SshInterceptor object that the FastPath must use whenever
    calling the Interceptor API functions.

    @param packet_handler
    Points to the packet handler callback function that the FastPath must
    use for passing packets to Engine.

    @param address_resolution
    Points to the packet handler callback function that the FastPath must
    use for passing APR and IPv6 neighbor discovery packets to Engine. This
    may be NULL if the Engine is not capable of processing address resolution
    packets.

    @param *flow_id_return
    The FastPath must fill in this return value parameter with a pointer to
    the flow id calculation routine that the Engine uses for flow id
    calculation.

    @param *fastpath_return
    The FastPath must fill in this return value parameter with a pointer to
    the FastPath object.

    @return
    If it returns FALSE, the fastpath is unusable.
*/
Boolean
fastpath_init(SshEngine engine,
              SshInterceptor interceptor,
              SshFastpathPacketCB packet_handler,
              SshFastpathPacketCB address_resolution,
              SshFastpathFlowIDCB *flow_id_return,
              SshFastpath *fastpath_return);

/** This function can be called to ensure that no more packets will be
    processed in asynchronous processes within the FastPath. The
    function returns TRUE if it was successful, and FALSE if there is
    currently asynchronous processing in effect that cannot be aborted. */
Boolean
fastpath_stop(SshFastpath fastpath);

/** This function uninitializes the FastPath. This function cannot be
    called before fastpath_stop() has successfully returned TRUE. */
void
fastpath_uninit(SshFastpath fastpath);

/** This function is called when the Engine / Policy Manager channel is opened.
    The FastPath should do any setup that is necessary. */
void
fastpath_notify_open(SshFastpath fastpath);

/** This function is called when the Engine / Policy Manager channel is closed.
    The FastPath should do any cleanup that is necessary. */
void
fastpath_notify_close(SshFastpath fastpath);

/** Suspend the FastPath. This needs to be called when the Engine is
    suspended e.g. in case of the computer is put to hibernation. */
void
fastpath_suspend(SshFastpath fastpath);

/** Resume the FastPath. This needs to be called to continue packet
    processing after the FastPath has been suspended. */
void
fastpath_resume(SshFastpath fastpath);

/** This function is used to notify the FastPath module of changes
    in Engine parameters. */
void
fastpath_set_params(SshFastpath fastpath, const SshEngineParams params);

/** This functions sends the salt used for randomizing the flow ID hash
    tables to the FastPath. This function is deprecated and the FastPath
    implementation is free to ignore the salt. */
void
fastpath_set_salt(SshFastpath fastpath, const unsigned char *salt,
                  size_t salt_len);


#ifdef SSH_IPSEC_STATISTICS
/*--------------------------------------------------------------------*/
/* Querying statistics information from the FastPath                  */
/*--------------------------------------------------------------------*/

/** Callback function for returning global statistics.  `stats' is the
    statistics, or NULL on failure.  The callback must copy `stats' if they
    are needed after this call. */
typedef void (*SshFastpathGlobalStatsCB)(SshEngine engine,
                                         const SshFastpathGlobalStats stats,
                                         void *context);

/** Retrieves global statistics information from the FastPath. `callback' will
    be called with `context' and `stats' either during this call or later; if
    the statistics could not be retrieved, then `stats' will be NULL.  The
    callback should copy the statistics if they are needed after the call. */
void fastpath_get_global_stats(SshFastpath fastpath,
                               SshFastpathGlobalStatsCB callback,
                               void *context);

#endif /* SSH_IPSEC_STATISTICS */


/*--------------------------------------------------------------------*/
/* LRU flow management                                                */
/*--------------------------------------------------------------------*/

/** This function returns the least recently used flow (of the active flows)
    in the fastpath that has an lru_level of at most 'lru_level' and does
    not have the SSH_ENGINE_FLOW_D_NO_LRU_REAP flag set. */
SshUInt32
fastpath_get_lru_flow(SshFastpath fastpath, SshUInt32 lru_level);


/*--------------------------------------------------------------------*/
/* Engine-To-FastPath                                                 */
/*--------------------------------------------------------------------*/

/** This function passes a packet from the Engine to the FastPath for
    processing. This continues processing of the packet according to
    `ret'. `context' points to a SshEnginePacketContext containing
    information for the packet. This function must eventually free
    pc->pp (by sending or freeing it), must update counters, and must
    free pc if dynamically allocated.

   This function must NOT be called with any locks held. */
void
fastpath_packet_continue(SshFastpath fastpath,
                         SshEnginePacketContext pc,
                         SshEngineActionRet ret);

#endif /* ENGINE_FASTPATH_H */
