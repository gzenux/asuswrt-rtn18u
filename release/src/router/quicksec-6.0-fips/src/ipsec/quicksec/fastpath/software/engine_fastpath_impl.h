/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the macros described in the engine_fastpath.h file.

   File: engine_fastpath_impl.h

   This header provides the implementation of the engine_fastpath.h macros.

   How these macros are implemented depends on whether a accelerated fastpath
   is configured.

   Preprocessor Defines
   ------------------------

   The following defines are used for deciding how the engine fastpath macros
   are implemented and how the flow, transform and next hops tables are
   managed by the system.

   FASTPATH_ACCELERATOR_CONFIGURED : If this define is set then an
   accelerated fastpath has been configured to the system. Note that when a
   fastpath accelerator is in use, the software fastpath will also be in use.
   The software fastpath is used as a backup fastpath, for example when the
   accelerated fastpath is unable to process a packet it passes the packet
   to the software fastpath for processing.

   The following three defines are set only if
   FASTPATH_ACCELERATOR_CONFIGURED is defined. These defines determine
   whether the accelerated fastpath or the software fastpath is responsible
   for managing the fastpath objects related to flows, transforms and next
   hops.

   FASTPATH_PROVIDES_FLOW : The accelerated fastpath is responsible for
                            maintaining the flow database. This define will
                            usually be set whenever a accelerated fastpath is
                            in use.

   FASTPATH_PROVIDES_TRD :  The accelerated fastpath is responsible for
                            maintaining the transform database. This define
                            will usually be set whenever a accelerated
                            fastpath is in use.

   FASTPATH_PROVIDES_NH :   The accelerated fastpath is responsible for
                            maintaining the next hop database. This define
                            will usually be set whenever a accelerated
                            fastpath is in use.

   For example, if the FASTPATH_PROVIDES_TRD define is set, the software
   fastpath does not allocate or manage transform data objects. This
   functionality is provided by the accelerated fastpath.

   In the case where there is no accelerated fastpath, i.e.
   FASTPATH_ACCELERATOR_CONFIGURED is undefined, then allocation and
   management of flows, transforms and next hop objects is provided by
   the software fastpath.

   engine_fastpath.h API macro implementation.
   -------------------------------------------

   The engine_fastpath.h macros fall into three families:

   a) flow accessors

   FASTPATH_INIT_FLOW
   FASTPATH_GET_FLOW
   FASTPATH_GET_READ_ONLY_FLOW
   FASTPATH_REKEY_FLOW
   FASTPATH_COMMIT_FLOW
   FASTPATH_UNINIT_FLOW
   FASTPATH_RELEASE_FLOW

   b) transform accessors

   FASTPATH_INIT_TRD
   FASTPATH_GET_TRD
   FASTPATH_GET_READ_ONLY_TRD
   FASTPATH_UNINIT_TRD
   FASTPATH_COMMIT_TRD
   FASTPATH_RELEASE_TRD

   c) next hop accessors

   FASTPATH_INIT_NH
   FASTPATH_GET_NH
   FASTPATH_GET_READ_ONLY_NH
   FASTPATH_COMMIT_NH
   FASTPATH_UNINIT_NH
   FASTPATH_RELEASE_NH

   When FASTPATH_ACCELERATOR_CONFIGURED is undefined (i.e. software only
   fastpath), the engine_fastpath.h macros are provided by this file. The
   flow, transform and next hop tables are allocated in fastpath_alloc.c and
   the accessors for a), b) and c) are defined to access the relevant object
   from the table while taking the appropriate lock on the object.

   If FASTPATH_PROVIDES_FLOW is defined then management of flow objects is
   implemented by the accelerated fastpath, in this case the accelerated
   fastpath also provides the implementation of the fastpath_accel_*_flow
   functions. If however FASTPATH_ACCELERATOR_CONFIGURED is defined but
   FASTPATH_PROVIDES_FLOW is undefined, this means that there is an
   accelerated fastpath, but management of flow objects is the responsibility
   of the software fastpath. In this scenario, the flow management is
   implemented by the software fastpath and the accelerated fastpath provides
   dummy implementations of the fastpath_accel_*_flow functions. Similar
   comments apply for transforms and next hops objects.

   Note on the FP_* versus the FASTPATH_* macros.
   ---------------------------------------------

   The FASTPATH_* macros must be provided by the fastpath implementation. They
   are used by the engine code whenever the engine needs to access a object
   owned by the fastpath. As discussed above, the actual implementation of
   these macros is provided either by the software fastpath or the accelerated
   fastpath depending on how the system is configured.

   In addition, the software fastpath needs to access fastpath objects. If
   there is no accelerated fastpath configured, then accessing such objects
   is simple as they are managed by the software fastpath. If however, an
   accelerated fastpath is present and the accelerated fastpath manages
   fastpath objects such as flows, then in order for the software fastpath
   to access the flow object it needs to execute a similar set of instructions
   as the engine does to access that object.

   The purpose of the FP_* macros is to define how the software fastpath
   accesses fastpath objects. The implementation of the FP_* macros again
   differs according to whether an accelerated fastpath is configured to
   the system or not.

   The FP_* macros should only be called from the software fastpath code. They
   must not be used by the engine to access fastpath objects. In addition, the
   software fastpath should not use the FASTPATH_* macros to access
   fastpath objects, the FP_* macros must be used for this.
*/

#ifndef ENGINE_FASTPATH_IMPL_H
#define ENGINE_FASTPATH_IMPL_H 1


/** Flow management */

SshEngineFlowData
fastpath_init_flow(SshFastpath fastpath, SshUInt32 flow_index);
#define FASTPATH_INIT_FLOW(fastpath, flow_index)                           \
   fastpath_init_flow(fastpath, flow_index)

SshEngineFlowData
fastpath_get_flow(SshFastpath fastpath, SshUInt32 flow_index);
#define FASTPATH_GET_FLOW(fastpath, flow_index)                            \
   fastpath_get_flow(fastpath, flow_index)

SshEngineFlowData
fastpath_get_read_only_flow(SshFastpath fastpath, SshUInt32 flow_index);
#define FASTPATH_GET_READ_ONLY_FLOW(fastpath, flow_index)                  \
   fastpath_get_read_only_flow(fastpath, flow_index)

void
fastpath_commit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                     SshEngineFlowData data);
#define FASTPATH_COMMIT_FLOW(fastpath, flow_index, flow)                   \
   fastpath_commit_flow(fastpath, flow_index, flow)

void
fastpath_uninit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                     SshEngineFlowData data);
#define FASTPATH_UNINIT_FLOW(fastpath, flow_index, flow)                   \
   fastpath_uninit_flow(fastpath, flow_index, flow)

void
fastpath_release_flow(SshFastpath fastpath, SshUInt32 flow_index);
#define FASTPATH_RELEASE_FLOW(fastpath, flow_index)                        \
   fastpath_release_flow(fastpath, flow_index)

void
fastpath_rekey_flow(SshFastpath fastpath, SshUInt32 flow_index);
#define FASTPATH_REKEY_FLOW(fastpath, flow_index)                          \
   fastpath_rekey_flow(fastpath, flow_index)


/** Transform management */

SshEngineTransformData
fastpath_init_trd(SshFastpath fastpath, SshUInt32 trd_index);
#define FASTPATH_INIT_TRD(fastpath, trd_index)                             \
    fastpath_init_trd(fastpath, (trd_index))

SshEngineTransformData
fastpath_get_trd(SshFastpath fastpath, SshUInt32 trd_index);
#define FASTPATH_GET_TRD(fastpath, trd_index)                              \
   fastpath_get_trd(fastpath, (trd_index))

SshEngineTransformData
fastpath_get_read_only_trd(SshFastpath fastpath, SshUInt32 trd_index);
#define FASTPATH_GET_READ_ONLY_TRD(fastpath, trd_index)                    \
   fastpath_get_read_only_trd(fastpath, (trd_index))

void
fastpath_commit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    SshEngineTransformData trd);
#define FASTPATH_COMMIT_TRD(fastpath, trd_index, trd)                      \
   fastpath_commit_trd(fastpath, (trd_index), (trd))

void
fastpath_uninit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    SshEngineTransformData trd);
#define FASTPATH_UNINIT_TRD(fastpath, trd_index, trd)                      \
    fastpath_uninit_trd(fastpath, (trd_index), (trd))

void
fastpath_release_trd(SshFastpath fastpath, SshUInt32 trd_index);
#define FASTPATH_RELEASE_TRD(fastpath, trd_index)                          \
   fastpath_release_trd(fastpath, (trd_index))


#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/** Nexthop management */

SshEngineNextHopData
fastpath_init_nh(SshFastpath fastpath, SshUInt32 nh_index);
#define FASTPATH_INIT_NH(fastpath, nh_index)                                \
    fastpath_init_nh(fastpath, (nh_index))

SshEngineNextHopData
fastpath_get_nh(SshFastpath fastpath, SshUInt32 nh_index);
#define FASTPATH_GET_NH(fastpath, nh_index)                                 \
    fastpath_get_nh(fastpath, (nh_index))

SshEngineNextHopData
fastpath_get_read_only_nh(SshFastpath fastpath, SshUInt32 nh_index);
#define FASTPATH_GET_READ_ONLY_NH(fastpath, nh_index)                       \
    fastpath_get_read_only_nh(fastpath, (nh_index))

void
fastpath_commit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                   SshEngineNextHopData nh);
#define FASTPATH_COMMIT_NH(fastpath, nh_index, nh)                          \
    fastpath_commit_nh(fastpath, (nh_index), (nh))

void
fastpath_uninit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                   SshEngineNextHopData nh);
#define FASTPATH_UNINIT_NH(fastpath, nh_index, nh)                          \
    fastpath_commit_nh(fastpath, (nh_index), (nh))

void
fastpath_release_nh(SshFastpath fastpath, SshUInt32 nh_index);
#define FASTPATH_RELEASE_NH(fastpath, nh_index)                             \
    fastpath_release_nh(fastpath, (nh_index))

#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/** IPv4 packet ID range for engine and software fastpath. This default
    range is used if the fastpath or accelerated fastpath does not define
    an exclusive IP ID range for the engine and software fastpath.*/
#ifndef FASTPATH_ENGINE_IP_ID_MIN
#define FASTPATH_ENGINE_IP_ID_MIN 0
#endif /* FASTPATH_ENGINE_IP_ID_MIN */

#ifndef FASTPATH_ENGINE_IP_ID_MAX
#define FASTPATH_ENGINE_IP_ID_MAX 0xffff
#endif /* FASTPATH_ENGINE_IP_ID_MAX */

/** IPv6 fragment ID range for engine and software fastpath. This default
    range is used if the fastpath or accelerated fastpath does not define
    an exclusive IPv6 frag ID range for the engine and software fastpath.*/
#ifndef FASTPATH_ENGINE_IPV6_FRAG_ID_MIN
#define FASTPATH_ENGINE_IPV6_FRAG_ID_MIN 0
#endif /* FASTPATH_ENGINE_IPV6_FRAG_ID_MIN */

#ifndef FASTPATH_ENGINE_IPV6_FRAG_ID_MAX
#define FASTPATH_ENGINE_IPV6_FRAG_ID_MAX 0xffffffff
#endif /* FASTPATH_ENGINE_IPV6_FRAG_ID_MAX */


#endif /* ENGINE_FASTPATH_IMPL_H */
