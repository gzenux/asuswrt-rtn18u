/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the SSH IPSEC engine.  Definitions in this
   file are typically used by transform implementations.

   This header file also includes the header files required by almost
   all of engine source files.
*/

#ifndef ENGINE_INTERNAL_H
#define ENGINE_INTERNAL_H

#include "ipsec_params.h"

#include "interceptor.h"
#include "ip_interfaces.h"
#include "quicksec_pm_shared.h"
#include "engine.h"

/* We need the user-mode timeouts for upcalls and for
   SshEngineAuditFlowEvent stuct. */
#include "sshtimeouts.h"

#include "engine_pm_api.h"
#include "engine_pme.h"
#include "kernel_encode.h"
#include "kernel_timeouts.h"
#include "kernel_mutex.h"
#include "kernel_alloc.h"
#include "engine_alloc.h"
#include "ip_cksum.h"
#include "version.h"
#include "sshinet.h"
#include "sshrand.h"
#include "sshcrypt.h"
#include "sshhash_i.h" /* needed for the PRNG */
#include "sshmp-xuint.h"
#include "sshcipher_i.h"
#include "sshmac_i.h"
#include "engine_hwaccel.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#include "virtual_adapter_internal.h"
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#ifdef SSHDIST_IPSEC_FIREWALL
#ifdef SSHDIST_IPSEC_NAT
/* All is good, SSHDIST_IPSEC_NAT defined for SSHDIST_IPSEC_FIREWALL */
#else /* SSHDIST_IPSEC_NAT */
#error SSHDIST_IPSEC_NAT is required when SSHDIST_IPSEC_FIREWALL is defined!
#endif /* SSHDIST_IPSEC_NAT */
#endif /* SSHDIST_IPSEC_FIREWALL */

#include "engine_rule_lookup.h"

/**********************************************************************
 * Macros for kernel _flags() memory allocations that do not have
 * analogies in the engine.
 *********************************************************************/
#ifdef USERMODE_ENGINE
#define ssh_malloc_flags(a, b)     ssh_malloc((a))
#define ssh_calloc_flags(a, b, c)  ssh_calloc((a), (b))
#define ssh_realloc_flags(a, b, c) ssh_realloc((a), (b))
#endif /* USERMODE_ENGINE */

/**********************************************************************
 * Primitives for allocating and freeing large arrays.
 *********************************************************************/

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
/* Allocate a two-dimension array of 'nelems' of size 'elem_size'
   split into blocks of 'page_size' elements.  Note that it could be
   possible to compute the "page_size" from the other parameters and
   SSH_ENGINE_MAX_MALLOC, but as most macros indexing the tables use
   this parameter it is kept as a parameter. This function zeros
   the actual array elements. */
void **ssh_engine_calloc_2d_table(SshEngine engine,
                                  SshUInt32 nelems,
                                  SshUInt32 page_size,
                                  SshUInt32 elem_size);

void ssh_engine_free_2d_table(SshEngine engine,
                              void **ptr,
                              SshUInt32 nelems,
                              SshUInt32 page_size);

#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */


/**********************************************************************
 * Some forward type declarations required later in this file.  This
 * Section also defines certain data types that are needed by other
 * internal include files e.g. as return value types.
 **********************************************************************/

/* Number of flow LRU levels. */
#define SSH_ENGINE_N_FLOW_LRU_LEVELS            16

/* Number of concurrent threads allowed to execute in the
   ssh_engine_packet_handler(). */
#define SSH_ENGINE_NUM_CONCURRENT_THREADS       16

/* Set the PMTU expire time to 5 minutes. */
#define SSH_ENGINE_FLOW_PMTU_EXPIRE_TIME (5 * 60)

/* Return value type for protocol-specific monitors (e.g.,
   engine_tcp.h). */
typedef enum {
  /* Pass the packet through (we may have modified pc). */
  SSH_ENGINE_MRET_PASS,

  /* Silently drop the packet. */
  SSH_ENGINE_MRET_DROP,

  /* Error causing 'pc->pp' to be freed occured in protocol monitor. Packet
     context 'pc' is still valid.  */
  SSH_ENGINE_MRET_ERROR,

  /* Drop the packet and send back ICMP. */
  SSH_ENGINE_MRET_REJECT
} SshEngineProtocolMonitorRet;

/* Data structure for describing next hop gateways and hosts that we
   communicate with.  Their access and manipulation is protected by
   engine->flow_control_table_lock and the fastpath lock both. */
typedef struct SshEngineNextHopControlRec *SshEngineNextHopControl;
typedef struct SshEngineNextHopRec *SshEngineNextHop;

/**********************************************************************
 * Include other internal engine header files which depend on the
 * types declared above.
 **********************************************************************/

#include "engine_tcp.h"
#include "engine_udp.h"
#include "engine_icmp.h"
#include "engine_fastpath_types.h"
#include "engine_fastpath_util.h"
#include "engine_fastpath.h"
#include "fastpath_impl.h"
#include "engine_arp.h"

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/**********************************************************************
 * Media header and link-layer protocol specific stuff.  Most of the
 * relevant code is in engine_mediatypes.c.
 **********************************************************************/

/* Constructs a media header for the given media type.  This returns the
   length of the media header (0 if no media header).  This also sets
   `*min_packet_len_return' to the minimum length of a packet when it is
   sent out (any packets shorter than that are padded with zeroes at the end
   to make them minimum length; 0 is returned if there is no minimum).
   The `mediahdr' buffer should be at least SSH_MAX_MEDIAHDR_SIZE bytes.
   When the media header is inserted on a packet, the resulting packet is
   of protocol `*protocol_return' (SSH_PROTOCOL_OTHER if it is not to be
   changed). */
size_t ssh_engine_make_media_header(SshInterceptorMedia mediatype,
                                    const unsigned char *src,
                                    const unsigned char *dst,
                                    SshUInt16 ethertype,
                                    unsigned char *mediahdr,
                                    size_t *min_packet_len_return,
                                    SshInterceptorProtocol *protocol_return);


/* Updates a media header for the given media type.  This returns the
   length of the media header (0 if no media header).  This also sets
   `*min_packet_len_return' to the minimum length of a packet when it is
   sent out (any packets shorter than that are padded with zeroes at the end
   to make them minimum length; 0 is returned if there is no minimum).
   The `mediahdr' buffer should be at least SSH_MAX_MEDIAHDR_SIZE bytes.
   When the media header is inserted on a packet, the resulting packet is
   of protocol `*protocol_return' (SSH_PROTOCOL_OTHER if it is not to be
   changed). */

size_t ssh_engine_modify_media_header(SshInterceptorMedia mediatype,
                                      const unsigned char *src,
                                      const unsigned char *dst,
                                      SshUInt16 ethertype,
                                      unsigned char *mediahdr);

/* The fastpath_insert_media_header() function checks if need to add media
   framing to packet 'pp'. This sets 'pp->protocol' and 'pc->media_hdr_len'
   according to the added media header. On error this returns FALSE and 'pp'
   has been freed already. */
Boolean
fastpath_insert_media_header(SshEnginePacketContext pc,
                             SshInterceptorPacket pp);

/** This function is not really a part of the fastpath API, but to avoid
    redundant functionality, this is called also directly from the engine.
    (ssh_engine_update_media_header is translated to
    fastpath_update_media_header  via a macro). */
void
fastpath_update_media_header(SshEnginePacketContext pc,
                             SshEngineNextHopData nh,
                             Boolean dst_is_nulladdr);

/* Update packet context's cached media header's source or destination
   media addresses for some special next-hop nodes.  The function
   handles two special cases in the media headers: for inbound
   next-hop nodes, it updates the packets source media address from
   the `pc->pp's cached media header that was stored there when the
   media framing was stripped from the packet.  For outbound packets
   to the `0.0.0.0' IP address, the function updates the packet's
   destination media address from the `pc->pp's cached media header to
   be the original media header.  The function does nothing if
   `pc->pp->pd's media protocol differs from `nh->media_protocol' or
   if the media type does not use media headers (plain interface). */
#define ssh_engine_update_media_header(pc, nh, dst_is_nulladdr) \
  fastpath_update_media_header((pc), (nh), (dst_is_nulladdr))

#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/**********************************************************************
 * Engine packet handler callbacks.                                   *
 **********************************************************************/

/* This callback function is passed to fastpath in fastpath_init(). The
   fastpath calls this to pass packets to Engine processing. */
void
engine_rule_packet_handler(SshEngine engine, SshEnginePacketContext pc);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* This callback function is passed to fastpath in fastpath_init(). The
   fastpath calls this to pass ARP and IPv6 neighbor discovery packets
   to Engine processing. */
void
engine_address_resolution(SshEngine engine, SshEnginePacketContext pc);

/* This function encapsulates the packet into an ethernet header, taking the
   source and destination ethernet addresses from `src' and `dst',
   respectively, and ethernet type field from `ethertype', and sends it
   out to the network (interface pp->ifnum, direction indicated by
   pp->flags).  This frees pp. */
void ssh_engine_encapsulate_and_send(SshEngine engine,
                                     SshInterceptorPacket pp,
                                     const unsigned char *src,
                                     const unsigned char *dst,
                                     SshUInt16 ethertype);

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Sends the given packet out using the engine.  This performs any required
   routing and ARP lookups for the packet, and applies the given transform
   on the packet before sending it (if transform_index is not
   SSH_IPSEC_INVALID_INDEX).  This frees pp.  `dst' must be the destination
   IP address of the packet.

   The `packet_len', `hdrlen' `ipproto', `ipsec_offset' and
   `ipsec_offset_prevnh' are copied into the generated
   SshEnginePacketContext and must correspond with the frame in 'pp'.
   The `ipsec_offset' and `ipsec_offset_prevnh' can safely be set to
   zero for IPv6 packets. The 'send_asynch' param states
   whether to guarantee that the packet is sent asynchronously
   and the callstack is "broken". This param should be TRUE
   for at least all generated response packets (TCP RST, ICMP
   destination unreachable, etc..).

   If packet is a generated packet sent to local stack, the `src' specifies
   the `sender' of the packet (remote host or next-hop gateway). */

void ssh_engine_send_packet(SshEngine engine, SshInterceptorPacket pp,
                            SshUInt16 hdrlen,
                            SshUInt32 transform_index,
                            const SshIpAddr src,
                            const SshIpAddr dst,
                            SshUInt8 ipproto,
                            SshUInt16 ipsec_offset,
                            SshUInt16 ipsec_offset_prevnh,
                            Boolean send_asynch);

/* A simple ratelimiter. This function returns TRUE if the packet
  should be dropped to a rate limit. The parameters src, dst, ipproto,
  param_a, param_b and checksum describe the packet triggering the response
  and NOT the response that will be sent. */
Boolean
ssh_engine_response_rate_limit(SshEngine engine,
                               const SshIpAddr src, const SshIpAddr dst,
                               SshUInt16 ipproto,
                               SshUInt16 param_a, SshUInt16 param_b,
                               SshUInt16 checksum);

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
/* A simple rate limitation for flows. This function returns TRUE if
   the flow creation should be prohibited due to a rate limit.
   The parameter src is the source address of the packet triggering
   the flow create and pc is the packet context for this packet.
   This function must be called with the 'engine->flow_control_table_lock'
   held. */
Boolean
ssh_engine_flow_rate_limit(SshEngine engine, const SshIpAddr src,
                           Boolean is_trusted);

/* This function should be called when a flow is freed. It will
   adjust the rate limitation bitmaps accordingly. The parameters
   for the function should be the same as those used in
   the corresponding call to ssh_engine_flow_rate_limit(),
   although this is not strict. This function must be called with
   the 'engine->flow_control_table_lock' held. */
void
ssh_engine_flow_rate_unlimit(SshEngine engine, const SshIpAddr src);
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

/* A simple rate limitation for auditing events. This function returns
   TRUE if the event should not be audited tue to rate limiting.
   This function must be called with the 'engine->flow_control_table_lock'
   held. 'audit_level' is the level of the generated audit event and must
   be less than SSH_ENGINE_NUM_AUDIT_LEVELS */
Boolean
ssh_engine_audit_rate_limit(SshEngine engine, SshUInt32 audit_level);

/* This function frees any resources on the queue of pending audit messages
   to the policy mananger, and should be called when stopping the engine.
   This function takes the flow control table lock. */
void ssh_engine_audit_uninit(SshEngine engine);

/* Adjust the flow MTU based on received PMTU message which is given
   in the PC as a input for this function. The pc flow_index needs to
   point into a valid flow. */
void
ssh_engine_pmtu_adjust_flow(SshEngine engine, SshEnginePacketContext pc);

/* Handle incoming ICMP Unreachable/Fragmentation Needed messages
   directed to one of our own IP addresses.  This should look up the
   appropriate transform and update its idea of the path MTU.  This
   returns SSH_ENGINE_RET_ERROR if an error occurs and causes pc->pp
   to be freed, SSH_ENGINE_RET_DEINITIALIZE if this processed the
   packet and it should not be sent forward (pc->pp has already been
   freed), and SSH_ENGINE_RET_OK if the packet should also be passed
   to normal rule-based processing. */
SshEngineActionRet ssh_engine_handle_pmtu_icmp(SshEngine engine,
                                               SshEnginePacketContext pc);




void
ssh_engine_pmtu_init(void);




void
engine_rule_packet_handler_init(void);

/* Function for passing packets to the fastpath from the engine. Do
   NOT call fastpath_packet_continue() directly, but instead use
   engine_packet_continue(). This function cleans up some engine rule
   execution specific state in the PacketContext before passing
   the packet to fastpath_packet_continue(pc, ret) as is. */
void
engine_packet_continue(SshEnginePacketContext pc, SshEngineActionRet ret);

/* Function for passing packets to the fastpath from the engine. This
   allocates a packet context and sends the packet to the fastpath using
   engine_packet_continue(). The argument `pc_flags' specifies the flags
   used in packet context initialization (SSH_ENGINE_PC_*). This returns
   FALSE if the packet could not be sent and TRUE otherwise. This function
   steals 'pp' and the caller must not touch it again. Note that this
   function bypasses the checks for recursive invocations to
   ssh_engine_packet_handler() in engine_fastpath.c and should not be called
   from a synchronous code path with the fastpath. This function is intended
   for passing packets generated by asynchronous events to the fastpath
   (such as packets from the policy manager or packets processed by timeouts
   such as NAT-T keepalives). */
Boolean
ssh_engine_packet_start(SshEngine engine, SshInterceptorPacket pp,
                        SshUInt32 tunnel_id, SshUInt32 prev_transform_index,
                        SshUInt32 pc_flags);


/**********************************************************************
 * Definition of SshEnginePacketData (the data that goes inside the
 * interceptor packet object).  This section also contains definitions
 * related to the interceptor packet object (`pp') itself, such as
 * additional flag bits.
 **********************************************************************/





/* Flags for packets, used internally by the engine.  These flags must
   match the mask 0xfffff000. */
#define SSH_ENGINE_P_MEDIAHDR     0x001000 /* saved media hdr exists */
#define SSH_ENGINE_P_ISFRAG       0x002000 /* packet is a fragment */
#define SSH_ENGINE_P_FIRSTFRAG    0x004000 /* packet is a first fragment */
#define SSH_ENGINE_P_LASTFRAG     0x008000 /* packet is a last fragment */
#define SSH_ENGINE_P_BROADCAST    0x010000 /* was media-level broadcast */
#define SSH_ENGINE_P_NOTRIGGER    0x020000 /* don't trigger with this packet */

/* The following bits are only valid for packets which have failed
   flow lookup. */
#define SSH_ENGINE_P_TOLOCAL      0x040000 /* dst is our local addr */
#define SSH_ENGINE_P_FROMLOCAL    0x080000 /* src is our local addr (stack) */

/* The following bit is a copy of the FROMADAPTER flag from the time
   the packet was received by the engine. This is used for setting
   SSH_ENGINE_PACKET_FORWARDED in ssh_engine_execute_send(). */
#define SSH_ENGINE_P_FROMADAPTER 0x0100000 /* from adapter */

/* If this packet has been reassembled from fragments, then this flag is
   set. */
#define SSH_ENGINE_P_WASFRAG     0x0200000 /* was fragmented. */

/* Mask of bits to clear when restarting packet. */
#define SSH_ENGINE_P_RESET_MASK  \
  (0x00000fff|SSH_ENGINE_P_FROMADAPTER|SSH_ENGINE_P_WASFRAG)

/* Data to store in the space reserved for upper-level data in interceptor
   packet structure. */
typedef struct SshEnginePacketDataRec
{
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Length of the media header in bytes.  This being zero indicates
     no media header. */
  SshUInt8 media_hdr_len;

  /* Media type for the saved media header. */
  SshUInt8 mediatype; /* SshInterceptorMedia */

  /* Minimum length of a packet after media encapsulation.  This is
     only checked for packets that have a media header (media_hdr_len
     != 0). */
  SshUInt8 min_packet_len;

  /* Protocol after adding media header.  */
  SshUInt8 media_protocol;

  /* Media source and destination addresses.  These are used by
     media-specific code.  This is valid if and only if
     SSH_ENGINE_P_MEDIACACHED is set in packet flags. */
  unsigned char mediahdr[SSH_MAX_MEDIAHDR_SIZE];
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Offset of this fragment in the packet (valid only in fragment magic). */
  SshUInt16 frag_ofs;

  /* Length of this fragment (valid only in fragment magic). */
  SshUInt16 frag_len;

  /* Length of headers in this fragment (valid only in fragment magic). */
  SshUInt16 frag_hdrlen;

#if defined (WITH_IPV6)
  /* Offset from the beginning of the packet of the next hop -field
     prior to the fragment extension header. */
  SshUInt16 frag_offset_prevnh;
#endif /* WITH_IPV6 */

  /* Number of bytes by which this fragment overlaps following fragments
     (valid only in fragment magic). */
  SshUInt16 frag_overlap;

  /* Flag bits (SSH_ENGINE_FRAG_*) (valid only in fragment magic). */
  SshUInt8 frag_flags;

  /* Tunnel id with which this packet is to be processed.  This is only
     valid when the packet is on the pc->pending_packets list. */
  SshUInt32 pending_tunnel_id;

  /* Flow id that will be set to pc->flow_id when processing the
     pending packet starts. */
  unsigned char pending_flow_id[SSH_ENGINE_FLOW_ID_SIZE];

  /* Action according to which we dispatch when processing the pending
     packet starts. */
  SshEngineActionRet pending_ret;
} *SshEnginePacketData;

/**********************************************************************
 * Flow id hash and flow table data structures.
 **********************************************************************/

/* Definition of flags in SshEngineFlowControlRec.control_flags */
#define SSH_ENGINE_FLOW_C_NOTIFY_DELETE   0x0001 /* Provide flow delete
                                                    notificaitons to pm */
#define SSH_ENGINE_FLOW_C_LOG_CONNECTIONS 0x0002 /* log connections */
#define SSH_ENGINE_FLOW_C_VALID           0x0004 /* node is valid */
#define SSH_ENGINE_FLOW_C_REROUTE_PENDING 0x0008 /* Reroute flow */

#define SSH_ENGINE_FLOW_C_REROUTE_I       0x0010 /* Reroute initiator side */
#define SSH_ENGINE_FLOW_C_REROUTE_R       0x0020 /* Reroute responder side */

#define SSH_ENGINE_FLOW_C_PRIMARY         0x0040 /* Primary incoming IPsec flow
                                                  */

#define SSH_ENGINE_FLOW_C_UNDEFINED       0x0080 /* Flow's are appgw flows
                                                    which are still being
                                                    defined. */
#define SSH_ENGINE_FLOW_C_TRIGGER         0x0100 /* This is a temporary
                                                    dangling flow for
                                                    generating triggers. */
#define SSH_ENGINE_FLOW_C_IPSECSOFTSENT   0x0800 /* soft event has been sent */
#define SSH_ENGINE_FLOW_C_IPSECINCOMING   0x1000 /* IPSEC incoming flow */
#define SSH_ENGINE_FLOW_C_REKEYOLD        0x2000 /* fwd id is old rekeyed id*/

/* The number of rekey events which will be sent to the policy manager
   before expiring the transform. */
#define SSH_ENGINE_MAX_REKEY_ATTEMPTS 3

typedef struct SshEngineFlowControlRec
{
  /* Index of the rule that created this flow. */
  SshUInt32 rule_index;

  /* Next and prev pointers for the doubly linked list used to contain all
     flows created by a particular rule. */
  SshUInt32 rule_next;
  SshUInt32 rule_prev;

  /* Next and prev pointers for the doubly linked list used to contain all
     flows that are associated with some control/mgmt related state. This
     means either the 'all free flows list', 'all dangling flows' or
     flows that reference a trd, but that trd is not accessible via
     'rule_index'. */
  SshUInt32 control_next;
  SshUInt32 control_prev;

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  SshUInt32 pair_flow_idx;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Peer id of the initiator of this flow. This is required for re-routing
     NAT-TRAVERSAL flows in the overlapping id case. */
  unsigned char initiator_peer_id[SSH_ENGINE_PEER_ID_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Number of seconds for which this flow is kept alive after the
     last packet passed through it.  Zero means that there is no idle
     expiration.  This value is protected using
     engine->flow_control_table_lock. */
  SshUInt32 idle_timeout;

  /* PMTU notification has been received to this flow if the pmtu_expire_time
     is non-zero. The value represents when the pmtu needs to be resetted
     back to the interface mtu. */
  SshTime forward_pmtu_expire_time;
  SshTime reverse_pmtu_expire_time;

  /* Lifetime of this flow since it's creation.
     Zero means that it has no hard expire at all.  This is measured in
     seconds from the time the flow was created. */
  SshTime hard_expire_time;

  /* DPD worry metric value. If an inbound IPSEC flow has been idle
     for this many seconds, the timeout mechanism will generate an
     event for the flow. */
  SshUInt16 metric;

  /* Control flags */
  SshUInt16 control_flags;

  /* The number of times we have sent the REKEY_REQUIRED event to the
     policy manager. */
  SshUInt8 rekey_attempts;
} SshEngineFlowControlStruct;

typedef struct SshEngineFlowControlRec *SshEngineFlowControl;

typedef struct SshEngineFlowRec
{
  SshEngineFlowDataStruct data;
  SshEngineFlowControlStruct control;
} SshEngineFlowStruct;

typedef struct SshEngineFlowRec *SshEngineFlow;

/**********************************************************************
 * Flow id computation.  Most of the relevant code is in
 * engine_flow_id.c.
 **********************************************************************/

/* Computes the flow id for a TCP or UDP session.  This can be used to
   compute the flow id when it uses IP addresses or port numbers that
   are different from those found in the packet (as is the case when
   NAT is being performed). */
Boolean ssh_engine_compute_tcpudp_flowid(SshEngine engine,
                                         SshUInt8 ipproto,
                                         SshUInt32 tunnel_id,
                                         const SshIpAddr src,
                                         const SshIpAddr dst,
                                         SshUInt16 src_port,
                                         SshUInt16 dst_port,
                                         const SshUInt32 *extension,
                                         unsigned char *flow_id,
                                         Boolean from_adapter);

/* Computes a flow id for incoming traffic according to the given
   transform.  This determines the outermost SPI for such traffic, and
   generates a flow id that will match with such incoming traffic.
   The generated flow id will be stored in `flow_id'.
   The flow id is always computed using the current SPIs. */
Boolean ssh_engine_compute_transform_flowid(SshEngine engine,
                                            SshEngineTransformData trd,
                                            SshIpAddr own_addr,
                                            SshUInt32 outer_tunnel_id,
                                            Boolean use_old_spis,
                                            unsigned char *flow_id);

/**********************************************************************
 * Next hop nodes.  These nodes identify next hop gateways and contain
 * cached information on how to communicate to the specified next hop
 * gateway.  These nodes contain cached media header information, and
 * the reference to a next hop gateway node from other nodes implies
 * cached routing information.
 **********************************************************************/

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Size of the next_hop_ifnum_hash table. */
#define SSH_ENGINE_NH_C_IFNUM_HASH_SIZE  127

/* Macros for accessing next hop control nodes. */
#define SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEngineNextHopControlStruct))

#ifdef DEBUG_LIGHT
#define SSH_ENGINE_GET_NH(engine, idx)                                       \
(((idx) >= engine->next_hop_hash_size                                        \
 ? ssh_fatal("next hop index out of bounds")                                 \
   , (SshEngineNextHopControl)NULL                                           \
 : &((engine)->next_hop_control_table_root                                   \
                                  [(idx)/SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE]   \
                                  [(idx)%SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE])))
#else /* DEBUG_LIGHT */
#define SSH_ENGINE_GET_NH(engine, idx)                                       \
(&((engine)->next_hop_control_table_root                                     \
                                [(idx)/SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE]     \
                                [(idx)%SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */

/** Assert that next hop node refcount does not overflow. */
#define SSH_ENGINE_NH_NODE_REFCNT_ASSERT(c_nh)  \
  SSH_ASSERT((c_nh)->refcnt <= 0xffffffff)







#define SSH_ENGINE_NH_NODE_TAKE_REF(c_nh)                               \
  do                                                                    \
    {                                                                   \
      SSH_ENGINE_NH_NODE_REFCNT_ASSERT(c_nh);                           \
      (c_nh)->refcnt++;                                                 \
      SSH_DEBUG(SSH_D_LOWOK, ("Incrementing nh node %p refcount to %d", \
                              (c_nh), (c_nh)->refcnt));                 \
    }                                                                   \
  while (0)

/* Data structure for describing next hop gateways and hosts that we
   communicate with.  Next hop nodes are protected by
   engine->flow_control_table_lock. */
typedef struct SshEngineNextHopControlRec
{
  /* Reference count for this next hop node.  When this decrements down to
     zero, the node should be freed. */
  SshUInt32 refcnt;

  /* Index of the next node on the address hash list. When the node is on
     the freelist, this is the index of the next node on the freelist. */
  SshUInt32 next;

  /* Index of the next node on the ifnum hash list. */
  SshUInt32 ifnum_hash_next;

} SshEngineNextHopControlStruct;


typedef struct SshEngineNextHopRec
{
  SshEngineNextHopControlStruct control;
  SshEngineNextHopDataStruct data;
} SshEngineNextHopStruct;


/* Lookup a next-hop node for the next-hop gateway `next_hop_gw' with
   flags `nh_node_flags'.  If there is no matching next-hop node, the
   function will allocate a new one with the attributes `ifnum',
   `mediatype', and `mtu'.  The function returns the next-hop node and
   its index in `index_return' or NULL and SSH_IPSEC_INVALID_INDEX in
   `index_return' if the allocation or lookup operation fails.  If the
   operation is successful, the function adds a reference to the
   returned next-hop node.  The function must be called holding
   `flow_table_lock'. If the next hop creation is ongoing, this
   function indicates it with optional argument nh_creation_ongoing.
   If this argument is defined and NULL is returned, the reference
   count of this next hop is increased. */
SshEngineNextHopControl
ssh_engine_lookup_nh_node(SshEngine engine,
                          SshIpAddr src_ip,
                          SshIpAddr next_hop_gw,
                          SshUInt32 nh_node_flags,
                          SshEngineIfnum ifnum,
                          SshInterceptorMedia mediatype,
                          size_t mtu,
                          SshUInt32 *index_return,
                          Boolean *nh_creation_ongoing);


/* Lookup a next hop entry from next hop cache and copy the cached media
   header. This function is used for next hop lookup in
   ssh_engine_send_packet() when creating the media header for a packet. */
Boolean
ssh_engine_get_nh_node_media_header(SshEngine engine,
                                    SshIpAddr src_ip,
                                    SshIpAddr next_hop_gw,
                                    SshEngineIfnum ifnum,
                                    SshUInt8 nh_flags,
                                    unsigned char *media_header,
                                    SshUInt8 *media_header_len,
                                    SshUInt8 *min_packet_len,
                                    SshUInt8 *media_protocol);

/* Update next-hop nodes MAC for the destination IP.  If there is no
   matching next-hop node, nothing is done. The function must be called
   holding `flow_table_lock'. */
void ssh_engine_update_nh_node_mac(SshEngine engine,
                                   SshIpAddr next_hop_gw,
                                   const SshEngineIfnum ifnum,
                                   const unsigned char *target_hw);

/* Mark matching next-hop nodes for rerouting. Argument 'prefix' is the
   IP address prefix used with 'prefix_len' and 'ifnum' is the interface
   number to use for matching. */
void ssh_engine_nh_node_reroute(SshEngine engine,
                                SshIpAddr prefix,
                                SshUInt8 prefix_len,
                                SshEngineIfnum ifnum);

/* Decrements the reference count of the given next hop node, and frees it
   if the reference count becomes zero.  This must be called with
   engine->flow_control_table_lock held. */
void ssh_engine_decrement_next_hop_refcnt(SshEngine engine,
                                          SshUInt32 next_hop_index);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/******************** Auditing. ***************************************/

/* A macro for incrementing pointers in the ring-buffer containing
   pending AuditEvents. */
#define SSH_ENGINE_AUDIT_RING_INC(engine, value)      \
(((value) + 1) % (engine)->audit_table_size)

/* The number of different queues used for storing pending audit events
   which will be sent to the policymanager. Audit events of highest priority
   are placed on the queue with index 0, those of the lowestv priority are
   placed on the queue of of index (SSH_ENGINE_NUM_AUDIT_LEVELS - 1).
   Currently only two queues are in use, this may be extended if found
   necessary. */
#define SSH_ENGINE_NUM_AUDIT_LEVELS   2

#define SSH_ENGINE_AUDIT_LEVEL_CORRUPTION       0
#define SSH_ENGINE_AUDIT_LEVEL_INFORMATIONAL  (SSH_ENGINE_NUM_AUDIT_LEVELS - 1)

/* Function used by audit data generators to notify that a new audit
   event is available. This will arrange the policy manager to collect
   audit events eventually.

   Function assumes the caller holds the
   engine->flow_control_table_lock. */
void engine_audit_new_event(SshEngine engine);

/* Function used by audit data generators to notify that the queue is
   getting full. Depending of the configuration this may, or may not
   request policy manager to grab the audit events.

   Function assumes the caller holds the
   engine->flow_control_table_lock. */
void engine_audit_busy(SshEngine engine);

/* Auditing of global events (non-packet related) */
void
engine_audit_event(SshEngine engine, SshAuditEvent event);

/**********************************************************************
 * Top-level packet processing functions.
 **********************************************************************/

/* This function is called whenever the interface list changes.  This
   function can be called concurrently with other functions, and it
   may also be possible that another interface callback is received
   before this completes. */
void ssh_engine_interfaces_callback(SshUInt32 nifs,
                                    SshInterceptorInterface *ifs,
                                    void *context);

/* Clear internal interface specific context data from all interfaces.
   This should be called when the engine is stopped. */
void ssh_engine_interfaces_clear(SshEngine engine);

/* Retrieves an IP address for the given interface in the given
   protocol. If the match_ip is defined, the interface ip has to match
   with mask to the given ip address.
   Engine->flow_control_table_lock must be held when this is
   called.  This returns TRUE if an address for that protocol was
   found; otherwise this returns FALSE. */
Boolean ssh_engine_get_ipaddr(SshEngine engine, SshEngineIfnum ifnum,
                              SshInterceptorProtocol protocol,
                              SshIpAddr match_ip,
                              SshIpAddr ip_addr_return);

/* Returns the offset of `addr' from `base', that is, the difference
   of the two addresses considered numerically.  This works for both
   IPv4 and IPv6.  The result is undefined if the difference does not fit
   in 32 bits (for IPv6). */
SshUInt32 ssh_engine_ipaddr_subtract(const SshIpAddr addr,
                                     const SshIpAddr base);

/* Sets `*result' to the IP address at `offset' from `base', that is,
   adds `offset' to the numerical value of `base'.  This works for IPv4 and
   IPv6, though at most 32 bit offsets are handled. */
void ssh_engine_ipaddr_add(SshIpAddr result,
                           const SshIpAddr base,
                           SshUInt32 offset);


/* Returns the offset of `addr' from `base', that is, the difference
   of the two addresses considered numerically.  This works for both
   IPv4 and IPv6. */
void ssh_engine_ipaddr_subtract_128(const SshIpAddr addr,
                                    const SshIpAddr base,
                                    SshXUInt128 difference);

/* Sets `*result' to the IP address at `offset' from `base', that is,
   adds `offset' to the numerical value of `base'.
   This works for IPv4 and IPv6. */
void ssh_engine_ipaddr_add_128(SshIpAddr result,
                               const SshIpAddr base,
                               SshXUInt128 offset);

/* Initializes the packet context for starting the processing of a new
   packet. pc->engine, pc->pp, pc->tunnel_id and pc->pending_packets
   are initialized based on the arguments provided. */
void ssh_engine_init_pc(SshEnginePacketContext pc,
                        SshEngine engine,
                        SshInterceptorPacket pp,
                        SshUInt32 tunnel_id,
                        SshInterceptorPacket pending_packets);

/* Copy packet context data that is relevant to packet processing.
   Currently this function is used for initializing pc's for packet
   fragments after fragmentation. */
void ssh_engine_copy_pc_data(SshEnginePacketContext dst_pc,
                             SshEnginePacketContext src_pc);

/* Find a flow for the packet context 'pc'. If a flow is found,
   then the flow index is returned and pc->flags SSH_ENGINE_PC_FORWARD
   is set to indicate whether this was a match against the forward
   flow id or the reverse flow id. If no flow is found then
   SSH_IPSEC_INVALID_INDEX is returned. 'engine->flow_control_table_lock'
   must be held during this call. */
SshUInt32
ssh_engine_get_flow_to_pc(SshEngine engine, SshEnginePacketContext pc);

/** This function is not really a part of the fastpath API again, but
    to avoid redundant functionality, this is called also directly
    from the engine.  (ssh_engine_copy_transform_data calls
    fastpath_copy_flow_data). */
void
fastpath_copy_flow_data(SshFastpath fastpath, SshEngineFlowData flow,
                        SshEnginePacketContext pc);

/** This function is not really a part of the fastpath API again, but
    to avoid redundant functionality, this is called also directly
    from the engine.  (ssh_engine_copy_transform_data calls
    fastpath_copy_transform_data). The caller must have the fastpath
    write lock taken. */
Boolean
fastpath_copy_transform_data(SshFastpath fastpath, SshEnginePacketContext pc);

/* Copies enough data from the transform indicated by pc->transform_index
   into pc, so that the transform can be executed.  This also allocates
   IP packet ids, increments outgoing packet count, etc as needed.
   Engine->flow_control_table_lock must be held when this is called.
   This function calls fastpath_copy_transform_data() currently. */
Boolean ssh_engine_copy_transform_data(SshEngine engine,
                                       SshEnginePacketContext pc);

/* This function pulls up all necessary information into
   SshEnginePacketContext pc and SshEnginePacketData pd from the
   SshInterceptorPacket `pc->pp'. Note that this function is NOT
   intended to immediately discard all "non-good" packets. It MUST
   return all "corrupted" packets, that are sufficiently "un-corrupt"
   to be handled by the auditing code. If the packet protocol is not
   media level then 'pd' may be NULL.

   The information which has been "pulled up", is related to the
   SshInterceptorProtocol which is returned. Note that pp->protocol
   MAY have been modified in the process, and can not be used as the
   basis of a sanity check.

   Given an IP packet, this will pull up UDP, TCP, and SCTP port
   numbers, and ICMP <type,code> tuples into given packet context.

   If a packet which should not be processed further is received, then
   this function returns SSH_PROTOCOL_NUM_PROTOCOLS, and fill
   appropriate auding information into packet context. */

SshInterceptorProtocol
ssh_engine_context_pullup(SshEngine engine,
                          SshEnginePacketContext pc,
                          SshEnginePacketData pd);

/**********************************************************************
 * Data structures and functions related to the implementation of
 * IPSEC transforms.
 **********************************************************************/

/* How many control transforms can be held per block? */
#define SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEngineTransformControlStruct))

/* Convenience macro for accessing the 2d transform array */
#define SSH_ENGINE_GET_TR_UNWRAPPED(engine, idx)        \
(((idx) >= (engine)->transform_table_size               \
  ?  ssh_fatal("transform index out of bounds")          \
    , (SshEngineTransformControl)NULL                     \
  : (&((engine)->transform_control_table_root           \
       [(idx) / SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE]        \
       [(idx) % SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE]))))

/* Get the transform data object corresponding to the TR index
   `trd_index'.  The function returns the transform object or
   NULL if the transform index is invalid. */
#define SSH_ENGINE_GET_TRD(engine, trd_index)                             \
 ((SSH_ENGINE_GET_TR_UNWRAPPED(engine,                                    \
                              (trd_index) & 0xffffff)->generation         \
     != ((trd_index) >> 24))                                              \
     ? NULL                                                               \
     : SSH_ENGINE_GET_TR_UNWRAPPED(engine, (trd_index) & 0xffffff))

/* Make a transform data index from the transform's index and its
   generation.  The wrapped indexes are used in the engine to identity
   transform objects.  They must be referenced with the
   SSH_ENGINE_GET_TR() macro. */
#define SSH_ENGINE_WRAP_TRD_INDEX(trd_index, generation)        \
(((trd_index) & 0x00ffffff) | ((SshUInt32) (generation) << 24))

/* Unwrap the transform data object index from a wrapped TRD index
   `trd_index'. */
#define SSH_ENGINE_UNWRAP_TRD_INDEX(trd_index)  \
((trd_index) & 0x00ffffff)

/* Assert that transform ref count does not overflow. */
#define SSH_ENGINE_TRD_REFCNT_ASSERT(trd)       \
  SSH_ASSERT((trd)->refcnt <= 0xffffffff)







/* Increments trd refcnt. */
#define SSH_ENGINE_INCREMENT_TRD_REFCNT(trd)                            \
  do {                                                                  \
    ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock); \
    SSH_ENGINE_TRD_REFCNT_ASSERT(trd);                                  \
    (trd)->refcnt++;                                                    \
    SSH_DEBUG(SSH_D_LOWOK, ("Incrementing trd %p refcount to %d",       \
                            (trd), (trd)->refcnt));                     \
  } while (0);

/* Per-transform statistics flags. */
#define SSH_ENGINE_STAT_T_MAC_FAIL      0x00000001
#define SSH_ENGINE_STAT_T_DROP          0x00000002
#define SSH_ENGINE_STAT_T_GARBAGE       0x00000004 /* garbage packet */
#define SSH_ENGINE_STAT_T_REPLAY        0x00000008 /* replay prevention drop */

/* Run-time data for a single transform.  Data is copied to this data
   structure from the transform data (trd) so that no locking is needed
   while executing the transform. */
typedef struct SshEngineTransformRunRec
{
  SshUInt32 statflags;
  SshUInt32 restart_tunnel_id;
  SshIpAddrStruct gw_addr;
  SshIpAddrStruct local_addr;
  SshUInt16 local_port;
#ifdef SSHDIST_L2TP
  SshUInt16 l2tp_local_port;
  SshUInt16 l2tp_remote_port;
  SshUInt16 l2tp_local_tunnel_id;
  SshUInt16 l2tp_local_session_id;
  SshUInt16 l2tp_remote_tunnel_id;
  SshUInt16 l2tp_remote_session_id;
  SshUInt16 l2tp_seq_ns;
  SshUInt16 l2tp_seq_nr;
  SshUInt8 l2tp_flags;
#endif /* SSHDIST_L2TP */
  SshEngineIfnum local_ifnum;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  SshUInt8 natt_flags;
  SshUInt16 remote_port;
  unsigned char natt_oa_l[SSH_IP_ADDR_SIZE];
  unsigned char natt_oa_r[SSH_IP_ADDR_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
  SshUInt32 tcp_encaps_conn_id;
#endif /* SSH_IPSEC_TCPENCAP */
  SshUInt8 packet_enlargement;
  SshUInt8 cipher_key_size;     /* Cipher key size in bytes. */
  SshUInt8 cipher_iv_size;      /* Cipher IV size in bytes. If this differs
                                   to the cipher block size, we are using
                                   counter mode encryption. */
  SshUInt8 cipher_nonce_size;   /* Cipher nonce size in bytes. */
  SshUInt8 mac_key_size;        /* MAC key size in bytes. */
  SshUInt16 myipid;    /* IP packet ID for tunnel outer IP header */
  SshUInt32 myspis[3]; /* Indexed by the "IN" numbers regardless of
                          packet direction. */
  unsigned char mykeymat[SSH_IPSEC_MAX_KEYMAT_LEN / 2]; /* At "IN" offsets. */

  SshUInt32 tr_index;

  SshUInt32 mycount_high; /* outgoing seq, or incoming win ofs */
  SshUInt32 mycount_low; /* outgoing seq, or incoming win ofs */

  SshUInt32 myreplaymask[SSH_ENGINE_REPLAY_WINDOW_WORDS];

  /* Combined level hardware acceleration context */
  SshHWAccel transform_accel;
  SshUInt32 accel_unsupported_mask;

  /* IPv4 DF bit processing when IPsec is performed. Possible values
     as in SshEngineTransformData */
  SshUInt16 df_bit_processing : 2;

  /* Restart packet processing after transform execution for another
     round of nested tunneling. */
  SshUInt8 restart_after_tre : 1;

  /* Level of tunnel nesting. Used for debugging and asserts. */
  SshUInt8 nesting_level;

} SshEngineTransformRunStruct, *SshEngineTransformRun;

/* Puts the transform `unwrapped_index' to the transform object
   freelist of the engine `engine'.  The transform index must be given
   as un unwrapped transform index.  The transform object must be
   freed and all references to and from it must have been removed.
   Engine->flow_control_table_lock must be held when this is called. */
void ssh_engine_transform_freelist_put(SshEngine engine,
                                       SshUInt32 unwrapped_index);

/* Decrements the reference count of the transform.  If the reference
   count becomes zero, frees the transform and releases its SPIs.
   Engine->flow_control_table_lock must be held when this is called. */
void ssh_engine_decrement_transform_refcnt(SshEngine engine,
                                           SshUInt32 transform_index);

/* Deletes all rules and flows referencing the trd.  This means the
   trd will be deleted (either immediately or when its reference count
   reaches zero).  This must be called with engine->flow_control_table_lock
   held.  Engine->flow_control_table_lock must be held when this is called. */
void ssh_engine_clear_and_delete_trd(SshEngine engine, SshUInt32 trd_index);

/* Activates new SPI value and key material for transform. */
void ssh_engine_rekey_activate_outbound(SshEngine engine,
                                        SshUInt32 transform_index);

/* The time the engine sends up a rekey event for the transform
   pointed to by incoming IPsec flow 'c_flow'. This should leave enough time
   for the policy manager to be able to process the event, perform the
   quickmode (possibly main-mode) negotiation and install the new rule.
   The rekey events are triggered SSH_ENGINE_MAX_REKEY_ATTEMPTS times
   at roughly equal intervals starting at `c_trd->lifetime'/20 before hard
   expiry, unless limited otherwise by
   SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME and
   SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME_MAX ipsec_params.h parameters. */

SshTime ssh_engine_transform_soft_event_time(SshEngine engine,
                                             SshEngineFlowControl c_flow,
                                             SshEngineTransformControl c_trd,
                                             SshUInt32 rekey_attempt);

#define SSH_ENGINE_IPSEC_SOFT_EVENT_TIME(engine, c_flow, c_trd, attempt) \
  ssh_engine_transform_soft_event_time(engine, c_flow, c_trd, attempt)

/* Simple macro to adjust ipsec incoming flow lifetimes in consideration
   of the soft event time. This limits the lifetime to be at least twice
   SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME. */
#define SSH_ENGINE_IPSEC_HARD_EXPIRE_TIME(life_seconds)               \
((life_seconds) == 0 ? 0                                              \
 : (((life_seconds) < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)     \
    ? (2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)                    \
    : (life_seconds)))

/* Utility function for setting the SPI values to the correct order in
   transforms that are sent to policy manager in transform delete callbacks. */
void ssh_engine_transform_event_normalize_spis(SshEngineTransform tr);


/**********************************************************************
 * Packet context data structure.  One of these objects is created
 * for every packet that enters the engine.  Normally the packet
 * context is stored on stack; however, if an asynchronous call is
 * made (typically only if the packet enters policy decision code
 * or if hardware acceleration is used), then the packet context needs
 * to be copied into dynamically allocated memory.  (Code should
 * take into account that the address of the packet context may change
 * when it is active - which does not preclude it from being stored in
 * data structures when it is inactive.)
 **********************************************************************/

/* States for ssh_engine_execute_transform. */
typedef enum {
  SSH_ENGINE_TRE_IN,            /* Next: inbound transform */
  SSH_ENGINE_TRE_OUT,           /* Next: outbound transform */
  SSH_ENGINE_TRE_SEND,          /* Next: send the packet out */
  SSH_ENGINE_TRE_RESTART        /* Next: restart with new tunnel id */
} SshEngineExecuteTransformState;

/* Rule execution state machine error codes and actions. */
typedef enum {
  /* Success */
  SSH_ENGINE_RULE_EXECUTE_ERROR_OK = 0,
  /* Error */
  SSH_ENGINE_RULE_EXECUTE_ERROR_FAILURE = 1,
  /* Error, send ICMP to packet originator. */
  SSH_ENGINE_RULE_EXECUTE_ERROR_SEND_ICMP = 2,
  /* Error, packet was dequeued from ARP queue. */
  SSH_ENGINE_RULE_EXECUTE_ERROR_PKT_DEQUEUED = 3
} SshEngineRuleExecuteError;

/* Flags for packet contexts.  The lowermost 12 bits are a copy of flow
   flags. Flag values covered by SSH_ENGINE_PC_PUBLIC_MASK are public and
   defined in engine_fastpath_types.h */
#define SSH_ENGINE_PC_FLOW_D_MASK         0xfff /* mask of flow data flags that
                                                   are copied to pc->flags. */
#define SSH_ENGINE_PC_PUBLIC_MASK        0x3000 /* mask of public pc flags. */
/*      SSH_ENGINE_PC_FORWARD            0x1000    "forward" direction */
/*      SSH_ENGINE_PC_IS_IPSEC           0x2000    is packet IPsec packet
                                                   directed to local stack. */

#define SSH_ENGINE_PC_DONE               0x8000 /* pc should be freed */
#define SSH_ENGINE_PC_DECREMENT_TTL     0x10000 /* copy of decrement_ttl flag*/
#define SSH_ENGINE_PC_SKIP_TRD_VERIFY   0x20000 /* Skip trd index verification
                                                   for decapsulated packets. */
#define SSH_ENGINE_PC_AUDIT_CORRUPT     0x40000 /* Audit packet if corrupt */
#define SSH_ENGINE_PC_OUTBOUND_CALL     0x80000 /* Outbound call in progress*/
#define SSH_ENGINE_PC_NAT_KEEP_PORT    0x100000 /* Flag for appgw_mappings */
#define SSH_ENGINE_PC_NAT_SHARE_PORT   0x200000 /* Flag for appgw_mappings */
#define SSH_ENGINE_PC_REROUTE_FLOW     0x400000 /* This is a flow reroute */
#define SSH_ENGINE_PC_HIT_TRIGGER      0x800000 /* This packet has hit a
                                                   a dangling trigger flow */
#define SSH_ENGINE_PC_FORWARDED       0x1000000 /* Flag for stat counters */
#define SSH_ENGINE_PC_OUTBOUND        0x2000000 /* Flag for stat counters */
#define SSH_ENGINE_PC_RESTARTED_OUT   0x4000000 /* Outbound restarted */
#define SSH_ENGINE_PC_ENFORCE_AUDIT   0x8000000 /* Drop if cannot audit */

/* How many packet contexts can be held per block? */
#define SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEnginePacketContextStruct))

#ifdef DEBUG_LIGHT
#define SSH_ENGINE_GET_PC(engine, idx)                                     \
(((idx) >= SSH_ENGINE_MAX_PACKET_CONTEXTS                                  \
 ? ssh_fatal("packet context index out of bounds")                         \
   , (SshEnginePacketContext)NULL                                          \
 :&((engine)->pc_table_root[(idx)/SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE]   \
                           [(idx)%SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE])))
#else
#define SSH_ENGINE_GET_PC(engine, idx)                                    \
(&((engine)->pc_table_root[(idx)/SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE]   \
                          [(idx)%SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */

typedef struct SshFastpathTransformContextRec *SshFastpathTransformContext;

/* Flag values for internal transform control flags. These values must fit
   into SSH_ENGINE_TR_C_INTERNAL_FLAG_MASK defined in engine_pm_api.h. */
/* Inbound direction has been rekeyed, outbound rekey is pending */
#define SSH_ENGINE_TR_C_REKEY_PENDING                  0x00010000
/* Delete is pending */
#define SSH_ENGINE_TR_C_DELETE_PENDING                 0x00020000
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
#define SSH_ENGINE_TR_C_NATT_KEEPALIVE_SENT            0x00040000
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
/* Incoming IPsec flow for this transform is ongoing */
#define SSH_ENGINE_TR_C_IPSEC_FLOW_REROUTE_ONGOING     0x00080000
/* Primary incoming IPsec flow has been created for this transform */
#define SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED     0x00100000
/* Transform has inactive outbound SPI and keying material installed */
#define SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE  0x00200000
/* Current outbound SPI has been invalidated from policymanager */
#define SSH_ENGINE_TR_C_OUTBOUND_SPI_INVALID           0x00400000

/* Callback function that is called when a transform has completed its
   work. */
typedef void (*SshFastpathTransformCB)(SshEnginePacketContext pc,
                                       SshEngineActionRet ret,
                                       void *context);

/* Initializer values for `recursed_ret' and `recursed_error' fields
   in SshEnginePacketContext. These values are used for asserting the
   correctness of tail recursion elimination logic in fastpath and
   engine rule execute. */
#define SSH_ENGINE_PC_RECURSED_RET_UNDEFINED 0xdeadbeee
#define SSH_ENGINE_PC_RECURSED_ERROR_UNDEFINED 0xdadadada

/* Packet context data structure.  One of these is created for every packet
   when it enters the engine. */
typedef struct SshEnginePacketContextRec
{
  /* Packet flags, lowermost 12 bits are copied from the flow flags. */
  SshUInt32 flags;

  /* The `ret' argument from a tail-recursive call to
     ssh_engine_packet_continue. */
  SshEngineActionRet recursed_ret;

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  /* This value specifies at which point in the fastpath state machine
     to reinject the packet to the fastpath accelerator. */
  SshEngineActionRet fastpath_accel_ret;
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  /* The `error' argument from a tail-recursive call to
     ssh_engine_execute_rule_step. */
  SshEngineRuleExecuteError recursed_error;

  /* Pointer to the engine object. */
  SshEngine engine;

  /* The packet being processed. */
  SshInterceptorPacket pp;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Length of the media header in the packet. This is set when parsing the
     packet headers before the media header is removed from the packet and
     at the late stage of packet processing when the media header is added
     to the packet. */
  SshUInt16 media_hdr_len;
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* List of pending packets to be processed.  If this is non-NULL, we
     will process each of these packets in sequence, one at a time,
     when we are done with the current packet.  See "deinitialize" in
     engine_fastpath.c. This is used e.g. in fragmagic
     (engine_fragment_reassembly.c). */
  SshInterceptorPacket pending_packets;

  /* Pointer to next packet context (on freelist), or pointer to next
     packet context, if waiting for ARP completion. */
  SshEnginePacketContext next;

  /* Tunnel identifier for the packet.  This is set to 0 when it enters
     the engine, and is set to a tunnel-specific value when the packet
     is decapsulated from a tunnel. */
  SshUInt32 tunnel_id;

#ifdef SSH_IPSEC_STATISTICS
  /* Bit vector for statistics counter updates. */
  SshUInt32 stat_vec[(SSH_ENGINE_NUM_STATS + 31) / 32];
#endif /* SSH_IPSEC_STATISTICS */

  /* Flow id for the packet. */
  unsigned char flow_id[SSH_ENGINE_FLOW_ID_SIZE];

  /* Original packet length when the packet entered the system. */
  size_t orig_len;

  /* Length of the packet buffer. */
  size_t packet_len;

#if defined (WITH_IPV6)
  /* Offset of the place where to insert AH, ESP and other headers. */
  SshUInt16 ipsec_offset;

  /* Offset of the next-header -field referring to the place where the
     AH, ESP etc. header is to be inserted. */
  SshUInt16 ipsec_offset_prevnh;

  /* If this packet is a fragment, then these fields contain the
     offset of the fragment extension header, and the offset of the
     next-hop field referring to it.

     If this packet is *not* a fragment, then these fields contain the
     offset of the place where the fragment header will be placed, and
     the offset of the next-hop field referring to it.  In other
     words, the `fragh_offset' contains the length of the
     unfragmentable part, i.e. ".. all headers up to and containing
     the Routing header if present, else the Hop-by-Hop header if
     present, otherwise only the IPv6 header." */
  SshUInt16 fragh_offset;
  SshUInt16 fragh_offset_prevnh;

  /* Offset of destination options extension header or zero if packet
     did not contain any destination options extension header. */
  SshUInt16 dsth_offset;
#endif /* WITH_IPV6 */

  /* Offset and identification of the fragment, should it be one. */
  SshUInt32 fragment_id;
  SshUInt16 fragment_offset;

  /* The CPU from which this packet context was allocated from. */
  unsigned int cpu;

  /* Length of the IP header in pp, or the offset of the first application
     header for IPv6. */
  SshUInt16 hdrlen;

  /* Number of bytes saved by compression for this packet. */
  SshUInt16 comp_savings;

  /* Total length of a fragmented packet.  This is only valid if
     pp->flags & SSH_ENGINE_P_LASTFRAG is set. */
  SshUInt16 frag_packet_size;

  /* Minimum size of complete packet, set by _pullup */
  SshUInt16 min_packet_size;

  /* The payload IP protocol or Next Header value for the first
     application header. */
  SshUInt8 ipproto;

  /* ICMP type. */
  SshUInt8 icmp_type;

  /* Transaction identifier for IP payload protocols (DHCP xid in
     particular), used on flow management. */
  SshUInt32 protocol_xid;

  /* The source and final destination IP addresses of the packet. */
  SshIpAddrStruct dst;
  SshIpAddrStruct src;

  /* Index of the flow that was found. This index is unwrapped, and
     can be directly passed to FP_GET_FLOW() and so forth. */
  SshUInt32 flow_index;

  /* Generation of the flow. This is a copy of the flow->generation
     value during the time of the flow lookup. */
  SshUInt8 flow_generation;

  /* Transform index that was applied to the packet.  If the packet
     goes through a chain of transforms, this is the first transform
     of the chain.  If the packet has not gone through a transform, this
     is SSH_IPSEC_INVALID_INDEX. */
  SshUInt32 transform_index;
  /* The transform that is being performed. If the packet has not gone
     through a transform, this is 0. */
  SshPmTransform transform;

  /* Transform index from before restart, or SSH_IPSEC_INVALID_INDEX if
     we have not restarted with this packet. */
  SshUInt32 prev_transform_index;

  /* Pointer to a policy rule to which the processing for this packet
     has a reference.  This is NULL if there is no such reference. */
  SshEnginePolicyRule rule;

  /* Counter for level of tunnel nesting.  For encapsulation, this counter
     is initialized to `nesting_level' of innermost transform, and it is
     decremented by one for each encapsulation. For decapsulation this counter
     is initialized to 0 of and is incremented by one for each decapsulation.
     This is used for sanity checking, asserting and debugging. */
  SshUInt8 transform_counter;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Route key selector that was used for routing this packet. */
  SshUInt32 route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  union { /* Union of data for various processing cases. */
    struct SshEnginePacketContextRuleRec {
      /* State for rule execution. */
      enum {
        SSH_ENGINE_ST_INIT,

        /* Forwarded packets. */
        SSH_ENGINE_ST_FW_ROUTE_TN_DST,
        SSH_ENGINE_ST_FW_ROUTE_TN_SRC,

        /* To-local (inbound) packets. */
        SSH_ENGINE_ST_TL_ROUTE_SRC,
        SSH_ENGINE_ST_TL_ROUTE_TN_SRC,

        /* From-local (outbound) packets. */
        SSH_ENGINE_ST_FL_ROUTE_TN_DST,
        SSH_ENGINE_ST_FL_ROUTE_DST,

        /* Loopback packets. */
        SSH_ENGINE_ST_LOOPBACK,

        /* Terminal state. */
        SSH_ENGINE_ST_FINAL
      } state;
      SshEngineIfnum ifnum_dst;
      SshEngineIfnum ifnum_src;
      SshUInt16 src_port;
      SshUInt16 dst_port;
      SshUInt32 spi;
      SshUInt8 icmp_code;
      SshUInt8 ttl; /* IPv4 TTL or IPv6 HL */
      SshUInt8 tos; /* IPv4 ToS or IPv6 priority */
      SshUInt32 route_selector;
#if defined (WITH_IPV6)
      SshUInt16 dsth_offset;
#endif /* WITH_IPV6 */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SshUInt16 mtu_dst;
      SshUInt16 mtu_src;
      SshUInt8 local_dst;
      SshUInt8 local_src;
      SshUInt32 route_selector_dst;
      SshUInt32 route_selector_src;
      SshUInt32 route_selector_appgw;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      /* Media header processing related data. */
      SshUInt32 next_hop_index_dst;
      SshUInt32 next_hop_index_src;
      SshInterceptorMedia to_mediatype;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      /* The fields below are used in rule execution. Note that they may
         not match pc->pp if rule execution is doing flow or next hop
         rerouting. */
      SshEngineIfnum ifnum_in;
      SshInterceptorProtocol pp_protocol;
      SshUInt32 pp_flags;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
      SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
      /* The fields below are used in flow rerouting only. */
      SshUInt32 flow_reroute_tunnel_id;
      SshUInt32 flow_reroute_prev_transform_index;
      /* The header_cache contains parsed protocol header
         fields. The data is valid only between calls to
         fastpath_packet_context_pullup() and to
         fastpath_packet_context_is_sane(). */
      struct SshEnginePacketContextHeaderCacheRec {
        /* TCP data offset, flags and urgent pointer. */
        SshUInt8 tcp_data_offset;
        SshUInt8 tcp_flags;
        SshUInt16 tcp_urgent;
        /* UDPLite checksum coverage. */
        SshUInt16 udplite_csum_cov;
      } header_cache;
    } rule;
    struct SshEnginePacketContextFlowRec {
      /* Smaller of mtu values (next-hop, path) */
      SshUInt16 mtu;
      SshEngineIfnum ifnum;
      SshUInt8 local;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SshUInt8 mediatype;
      SshUInt8 media_protocol;
      SshUInt8 media_hdr_len;
      SshUInt8 min_packet_len;
      unsigned char mediahdr[SSH_MAX_MEDIAHDR_SIZE];
#endif /* SSH_IPSEC_IP _ONLY_INTERCEPTOR */
#ifdef SSHDIST_IPSEC_NAT
      SshIpAddrStruct nat_src_ip;
      SshIpAddrStruct nat_dst_ip;
      SshUInt16 nat_src_port;
      SshUInt16 nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */
      /**** Data for transform execution *****/
      SshEngineTransformRunStruct tr;
      SshEngineExecuteTransformState tre_state;
      /***** Data used during single transform execution *****/
#define SSH_FASTPATH_TRANSFORM_IN_ANTIREPLAY_DONE  0x01
      SshUInt8 crypto_state;
      SshUInt32 seq_num_low;
      SshUInt32 seq_num_high;
      SshUInt16 mac_ofs;
      SshUInt16 mac_len;
      SshUInt16 mac_icv_ofs;
#if defined(SSH_IPSEC_AH) && SSH_IPSEC_MAX_HMAC_OUTPUT_BITS < 192
/* With GMAC-AH we need to reserve space for HMAC and IV in ICV. */
      unsigned char packet_icv[192 / 8];
#else
      unsigned char packet_icv[(SSH_IPSEC_MAX_HMAC_OUTPUT_BITS+7) / 8];
#endif
      SshEngineTransformRun trr;
      SshFastpathTransformCB tr_callback;
      void *tr_context;
      SshFastpathTransformContext tc;
#ifdef SSHDIST_IPSEC_NAT
      SshIpAddrStruct internal_nat_ip;
      SshUInt16 internal_nat_port;
#endif /* SSHDIST_IPSEC_NAT */
    } flow;
  } u;

  /* Note; audit substructure needs to be present at the system even
     if auditing would be disabled, as some fields are used outside of
     the audit mechanisms. */
  struct SshEnginePacketContextAuditRec {
    /* Packet corruption status. */
    SshEnginePacketCorruption corruption;

    /* Parameter to SshEnginePacketCorruption */
    SshUInt32 ip_option;

    /* Parameters to audit ; SPI and sequence number */
    SshUInt32 flowlabel; /* This is also used by rule execute for routing */
    SshUInt32 spi;
    SshUInt32 seq;       /* This is also used for HW accels that do not
                            perform antireplay themselves. */
  } audit;

  struct SshEnginePacketErrorInfo {
    SshUInt32 icmp_extra_data;

#define SSH_ENGINE_SEND_TCP_REJECT  0x0001
#define SSH_ENGINE_SEND_ICMP_ERROR  0x0002
    SshUInt16 flags;

    SshUInt8 icmp_type;
    SshUInt8 icmp_code;
  } error_info;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Data for ARP lookups. */
  SshEngineArpComplete arp_callback;
  SshEngineIfnum arp_ifnum;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  Boolean on_freelist; /* TRUE if the packet context is on the freelist */
} SshEnginePacketContextStruct; /* ptr defined earlier */


/* Internal utility macro for fetching packet data from pc in read only mode.*/

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#define SSH_ENGINE_PC_IP_OFFSET(pc, offset) ((offset) + (pc)->media_hdr_len)
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#define SSH_ENGINE_PC_IP_OFFSET(pc, offset) (offset)
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#define SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, bytes, buf)          \
  do                                                                    \
    {                                                                   \
      SSH_ASSERT((bytes) <= sizeof((buf)));                             \
      if (SSH_ENGINE_PC_IP_OFFSET((pc), (offset) + (bytes)) <=          \
          SSH_INTERCEPTOR_MAX_PULLUP_LEN)                               \
        {                                                               \
          (ucp) = ssh_interceptor_packet_pullup_read                    \
            ((pc)->pp, (SSH_ENGINE_PC_IP_OFFSET((pc), (offset) + (bytes)))); \
          if ((ucp) != NULL)                                            \
            (ucp) += SSH_ENGINE_PC_IP_OFFSET((pc), (offset));           \
        }                                                               \
      else                                                              \
        {                                                               \
          ssh_interceptor_packet_copyout((pc)->pp,                      \
                                         SSH_ENGINE_PC_IP_OFFSET((pc),  \
                                                                 (offset)), \
                                         (buf), (bytes));               \
          (ucp) = (buf);                                                \
        }                                                               \
    }                                                                   \
  while (0)


/**********************************************************************
 * Data structure for the engine itself.
 **********************************************************************/

/* Size of the bitmap used to limit the rate of trigger messages sent.
   The size is in bits, and should be a prime. */
#define SSH_TRIGGER_BITMAP_SIZE 1009
#define SSH_TRIGGER_BITMAP_WORDS ((SSH_TRIGGER_BITMAP_SIZE + 31) / 32)

/* Function to clear trigger bitmap */
void ssh_engine_trigger_clear(void *context);

/* Function to initialize trigger module. Currently does nothing. */
Boolean ssh_engine_trigger_init(SshEngine engine);

/* Function to uninitialize trigger module. This cancels all trigger
   timeouts and frees pending trigger contexts. */
void ssh_engine_trigger_uninit(SshEngine engine);

/* Size of the bitmap used to limit the rate of ICMP messages sent.
   The size is in bits, and should be a prime. */
#define SSH_ICMP_BITMAP_SIZE    101

/* Function to clear ICMP bitmap */
void ssh_engine_response_rate_limit_clear(void *context);

#ifdef SSH_IPSEC_INTERNAL_ROUTING
/* Data structure for describing a route in the engine. */
typedef struct SshEngineRouteRec
{
  SshUInt32 flags; /* See SSH_PME_ROUTE_* bit masks below. */
  SshIpAddrStruct dst_and_mask;
  SshIpAddrStruct next_hop;
  SshEngineIfnum ifnum;
} SshEngineRouteStruct, *SshEngineRoute;
#endif /* SSH_IPSEC_INTERNAL_ROUTING */


/* Per-interface information that the engine stores in addition to
   information provided by the interceptor. These are currently
   allocated during interface change callbacks in the engine
   and pointers to these are stored in the 'ctx_user' fields
   of SshInterceptorInterface. */
typedef struct SshEngineIfInfoRec
{
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifdef WITH_IPV6
  /* Following needed by ARP module. */
  SshEngineArpPrefixInfo prefix_list;
  SshUInt16 num_prefixes;

  SshEngineArpRouterInfo router_list;
  SshUInt16 num_routers;

  SshUInt32 ipv6_reachable_time_msec;
  SshUInt32 ipv6_retrans_timer_msec;
#endif /* WITH_IPV6 */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#ifdef SSHDIST_IPSEC_NAT
  /* Information for NAT.  Note that the external IP address(es) used are
     taken from the outside interface. */
  SshPmNatType nat_type;

  /* If set will also NAT IPv6 addresses. */
  SshPmNatFlags nat_flags;

  /* Parameters for HOST NAT */
  SshIpAddrStruct host_nat_ext_base;
  SshIpAddrStruct host_nat_int_base;
  SshUInt32 host_nat_num_ips;
#endif /* SSHDIST_IPSEC_NAT */
} SshEngineIfInfoStruct, *SshEngineIfInfo;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/** Free default router and prefix lists from interface 'if_info'. */
void ssh_engine_arp_if_info_free(SshEngine engine,
                                 SshEngineIfInfo if_info);

/** Check reachability for 'next_hop' via interface 'ifnum'. */
Boolean ssh_engine_arp_check_reachability(SshEngine engine,
                                          SshIpAddr next_hop,
                                          SshEngineIfnum ifnum);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


typedef struct SshEnginePolicyRuleSetRec *SshEnginePolicyRuleSet;
typedef struct SshEnginePolicyRuleSetRec  SshEnginePolicyRuleSetStruct;


#ifdef SSHDIST_IPSEC_NAT
/* Maximum number of  <IP:PORT> port nat entries. Each flow contains 2
   entries and each engine rule 3 entries. */
#define SSH_ENGINE_FLOW_NAT_TABLE_SIZE \
        (2 * SSH_ENGINE_MAX_SESSIONS + 3 * SSH_ENGINE_MAX_RULES + 10)

/* How many port NAT contexts can be held per block? */
#define SSH_ENGINE_FLOW_NAT_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEngineNatPortStruct))

#ifdef DEBUG_LIGHT
#define SSH_ENGINE_GET_NAT_PORT(engine, idx)                             \
(((idx) >= SSH_ENGINE_FLOW_NAT_TABLE_SIZE                                \
 ? ssh_fatal("port NAT index out of bounds")                             \
   , (SshEngineNatPort)NULL                                              \
 :&((engine)->nat_port_table_root[(idx)/SSH_ENGINE_FLOW_NAT_BLOCK_SIZE] \
                           [(idx)%SSH_ENGINE_FLOW_NAT_BLOCK_SIZE])))
#else
#define SSH_ENGINE_GET_NAT_PORT(engine, idx)                             \
(&((engine)->nat_port_table_root[(idx)/SSH_ENGINE_FLOW_NAT_BLOCK_SIZE]  \
                          [(idx)%SSH_ENGINE_FLOW_NAT_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_ENGINE_PRNG

/*************** A simple PRNG (port of sshrand.c) in the engine ***********/

/* Must be at least 16 bytes */
#define SSH_ENGINE_RANDOM_STATE_BYTES 64
#define SSH_ENGINE_RANDOM_MD5_KEY_BYTES 16

typedef struct SshEngineRandomStateRec
{
  unsigned char state[SSH_ENGINE_RANDOM_STATE_BYTES];
  unsigned char stir_key[SSH_ENGINE_RANDOM_MD5_KEY_BYTES];
  size_t next_available_byte;
  size_t add_position;
} *SshEngineRandomState, SshEngineRandomStateStruct;

SshUInt8
ssh_engine_random_get_byte(SshEngine engine);

void
ssh_engine_random_add_entropy(SshEngine engine,
                              const unsigned char *buf,
                              size_t buflen);

void
ssh_engine_random_stir(SshEngine engine);

void
ssh_engine_random_uninit(SshEngine engine);

void
ssh_engine_random_init(SshEngine engine);

#endif /* SSH_ENGINE_PRNG */

#ifdef SSH_IPSEC_SEND_IS_SYNC
/* Data to store in the space reserved for upper-level data in
   interceptor packet structure while packets are queued for an
   asynchronous send by ssh_engine_send_packet() or
   ssh_engine_packet_handler().  The intention is to stop potentially
   dangerous recursive calls into the local stack. */
typedef struct SshEngineAsynchPacketDataRec
{
  /* The operation that should be performed for the packet: send or
     packet handler processing. */
  Boolean is_icept_send;

  /* Arguments of the ssh_engine_send_packet() call. */
  SshInterceptorPacket next;
  SshUInt32 transform_index;
  SshUInt16 hdrlen;
  SshUInt16 ipsec_offset;
  SshUInt16 ipsec_offset_prevnh;
  SshUInt8 ipproto;
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  size_t media_hdr_len;

  /* Arguments of the ssh_engine_packet_handler() call. */
  SshUInt32 tunnel_id;
  SshUInt32 prev_transform_index;
} SshEngineAsynchPacketDataStruct, *SshEngineAsynchPacketData;

/* A timeout function that processes queued packets from recursive
   ssh_engine_packet_handler invocations and packets requiring an
   asynchronous send from ssh_engine_packet_send().  If
   engine->recursive_timeout_scheduled is TRUE then this timeout is
   scheduled and if it is FALSE then it is not. */
void ssh_engine_process_asynch_packets(void *context);
#endif /* SSH_IPSEC_SEND_IS_SYNC */

/* The engine flow index is composed of a pair (generation, index) of
   flow indices. The generation is incremented very time a flow is
   created with that index. This provides a mechanism where a race condition
   can be detected with very high probability over short time-intervals
   without complex synch protocols over asynch interfaces.

   A flow_index encoded using SSH_ENGINE_FLOW_WRAP_INDEX into a 32-bit
   integer is called a "wrapped" index. SSH_IPSEC_INVALID_INDEX represents
   an invalid value for both wrapped and unwrapped indices. */

/* Bits used for the actual index */
#define SSH_ENGINE_FLOW_INDEX_MASK 0x00ffffff

/* Bits used for the generation */
#define SSH_ENGINE_FLOW_GEN_MASK   (~((SshUInt32)SSH_ENGINE_FLOW_INDEX_MASK))

/* Create a representation of flow index (generation, index) */
#define SSH_ENGINE_FLOW_WRAP_INDEX(generation, index) \
  ((((SshUInt32) generation) << 24) | (index))

/* Parse out the generation from such a representation */
#define SSH_ENGINE_FLOW_UNWRAP_GENERATION(index) \
  (((index) & SSH_ENGINE_FLOW_GEN_MASK) >> 24)

/* Parse out the index from such a representation */
#define SSH_ENGINE_FLOW_UNWRAP_INDEX(index)  \
  ((index) & SSH_ENGINE_FLOW_INDEX_MASK)

/* A convenience macro for the size of flow table array blocks. */
#define SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEngineFlowControlStruct))

/* Macro for fetching flow "flow_index" */
#ifdef DEBUG_LIGHT
#define SSH_ENGINE_GET_FLOW(engine, flow_index)                          \
(((flow_index) >= (engine)->flow_table_size                              \
  ? ssh_fatal("flow index 0x%x out of bounds", (unsigned int) flow_index)\
    , (SshEngineFlowControl)NULL                                         \
: &(engine)->flow_control_table_root                                     \
                    [(flow_index) / SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE]  \
                    [(flow_index) % SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE]))
#else /* DEBUG_LIGHT */
#define SSH_ENGINE_GET_FLOW(engine, flow_index)                           \
   (&((engine)->flow_control_table_root                                   \
                    [(flow_index) / SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE]   \
                    [(flow_index) % SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */



/* Macro for size of the rule table array blocks. */
#define SSH_ENGINE_RULE_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshEnginePolicyRuleStruct))

/* Macro for fetching rule 'rule_index' */
#ifdef DEBUG_LIGHT
#define SSH_ENGINE_GET_RULE(engine, rule_index) \
(((rule_index) >= (engine)->rule_table_size \
  ? ssh_fatal("rule index %d out of bounds", (int) rule_index) \
    , (SshEnginePolicyRule)NULL \
: &(engine)->rule_table_root[(rule_index) / SSH_ENGINE_RULE_TABLE_BLOCK_SIZE]\
                            [(rule_index) % SSH_ENGINE_RULE_TABLE_BLOCK_SIZE]))
#else
#define SSH_ENGINE_GET_RULE(engine, rule_index) \
(&((engine)->rule_table_root[(rule_index) / SSH_ENGINE_RULE_TABLE_BLOCK_SIZE] \
                            [(rule_index) % SSH_ENGINE_RULE_TABLE_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */

/* Get the index of a rule */
#define SSH_ENGINE_GET_RULE_INDEX(engine, rule) \
((rule)->rule_index)

/* Initialize a SshEnginePolicyRule */
#define SSH_ENGINE_RULE_INIT(rule)                        \
do {                                                      \
  memset((rule), 0, sizeof(*(rule)));                     \
  (rule)->selector_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM; \
  (rule)->transform_index = SSH_IPSEC_INVALID_INDEX;      \
  (rule)->depends_on = SSH_IPSEC_INVALID_INDEX;           \
  (rule)->dependent_rules = SSH_IPSEC_INVALID_INDEX;      \
  (rule)->dep_next = SSH_IPSEC_INVALID_INDEX;             \
  (rule)->dep_prev = SSH_IPSEC_INVALID_INDEX;             \
  (rule)->flows = SSH_IPSEC_INVALID_INDEX;                \
  (rule)->incoming_ipsec_flow = SSH_IPSEC_INVALID_INDEX;  \
  (rule)->trd_next = SSH_IPSEC_INVALID_INDEX;             \
} while (0);

/* Assert that rule refcount does not overflow. */
#define SSH_ENGINE_RULE_REFCNT_ASSERT(rule)     \
  SSH_ASSERT((rule)->refcnt <= 0xffffffff)







/* Increments rule refcnt. */
#define SSH_ENGINE_INCREMENT_RULE_REFCNT(rule)                          \
  do {                                                                  \
    ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock); \
    SSH_ENGINE_RULE_REFCNT_ASSERT(rule);                                \
    (rule)->refcnt++;                                                   \
    SSH_DEBUG(SSH_D_LOWOK, ("Incrementing rule %lu refcount to %d",     \
                            (rule)->rule_index, (rule)->refcnt));       \
  } while (0);

#ifdef SSH_IPSEC_TCPENCAP
/******************************** TCP encapsulation *************************/

/* Configuration data object. */
typedef struct SshEngineTcpEncapsConfigRec
{
  struct SshEngineTcpEncapsConfigRec *next;

  /* Address range of peer */
  SshIpAddrStruct peer_lo_addr;
  SshIpAddrStruct peer_hi_addr;
  SshUInt16 peer_port;

  /* Local address and TCP port */
  SshIpAddrStruct local_addr;
  SshUInt16 local_port;

  /* IKE ports */
  SshUInt16 local_ike_port;
  SshUInt16 remote_ike_port;

} SshEngineTcpEncapsConfigStruct, *SshEngineTcpEncapsConfig;

typedef struct SshEngineTcpEncapsConnRec *SshEngineTcpEncapsConn;
typedef struct SshEngineTcpEncapsDeleteRec *SshEngineTcpEncapsDelete;
#endif /* SSH_IPSEC_TCPENCAP */

/* The number of default engines rules. Such rules exist in the system whether
   or not the policymanager is loaded. Currently there are 4 default rules,
   a pass and drop rule, and a pass rule for DHCP requests from the local
   stack (one for IPv4 and one for IPv6). */
#define SSH_ENGINE_NUM_DEFAULT_RULES 6

/* Context data for engine age timeout callback. This object contains
   temporary data structures that are too big to be allocated from stack. */
#define SSH_ENGINE_AGE_TIMEOUT_MAX_TO_AGE 100

typedef struct SshEngineAgeCallbackContextRec
{
  struct
  {
    SshUInt32 flow_index;
    SshUInt32 trd_index;
    SshUInt32 rule_index;
    SshUInt8 flow_generation;
    SshPmeFlowEvent event;
  } to_be_freed[SSH_ENGINE_AGE_TIMEOUT_MAX_TO_AGE];

  SshEngineFlowDataStruct d_flow_copy;
  SshEngineTransformStruct tr;
  SshEnginePolicyRuleStruct ruledata;
} SshEngineAgeCallbackContextStruct, *SshEngineAgeCallbackContext;

/* Utility macros for adding and subtracting timestamps. These macros
   take each timestamp as combination of SshTime seconds and SshUInt32
   microseconds. */

/* Add time (a_sec, a_usec) to (b_sec, b_usec) and store result to
   (r_sec, r_usec). */
#define SSH_ENGINE_TIME_ADD(r_sec, r_usec, a_sec, a_usec, b_sec, b_usec) \
  do                                                                    \
    {                                                                   \
      (r_sec) = (a_sec) + (b_sec);                                      \
      (r_usec) = (a_usec) + (b_usec);                                   \
      if ((r_usec) >= 1000000)                                          \
        {                                                               \
          (r_sec)++;                                                    \
          (r_usec) -= 1000000;                                          \
        }                                                               \
    }                                                                   \
  while (0)

/* Subtract (b_sec, b_usec) from (a_sec, a_usec) and store result to
   (r_sec, r_usec). This asserts that a is larger or equal to b. */
#define SSH_ENGINE_TIME_SUB(r_sec, r_usec, a_sec, a_usec, b_sec, b_usec) \
  do                                                                    \
    {                                                                   \
      (r_sec) = (a_sec) - (b_sec);                                      \
      if ((a_usec) < (b_usec))                                          \
        {                                                               \
          SSH_ASSERT((r_sec) > 0);                                      \
          (r_sec)--;                                                    \
          (r_usec) = 1000000 + (a_usec) - (b_usec);                     \
        }                                                               \
      else                                                              \
        {                                                               \
          (r_usec) = (a_usec) - (b_usec);                               \
        }                                                               \
    }                                                                   \
  while (0)

/********************* CPU context ***********************************/
#define SSH_ENGINE_TAIL_RECURSION_DETECT       0x0001
typedef struct SshEngineCpuCtxRec
{
  SshUInt32 flags;

  /* Used along with SSH_FASTPATH_FLAG_TAIL_RECURSION_DETECT. */
  SshKernelMutexStruct pkt_list_lock;
  SshEnginePacketContext recursive_pkt_list;
  SshEnginePacketContext recursive_pkt_list_tail;
} SshEngineCpuCtxStruct, *SshEngineCpuCtx;

/* Context structure for keeping information about a trigger.  This is
   needed for getting the required information into the timeout function
   that actually calls ssh_pmp_trigger.  (Note that we cannot use `pc',
   because it will likely be freed before the callback occurs.) */
typedef struct SshEngineTriggerContextRec SshEngineTriggerContextStruct;
typedef struct SshEngineTriggerContextRec *SshEngineTriggerContext;

/* The main data structure for the engine.  There is typically only one of
   these objects in each system. */
typedef struct SshEngineRec
{
#ifdef USERMODE_ENGINE
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

  /* Stack size to use in kernelmode */
  SshUInt32 kernelmode_stacksize;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
#endif /* USERMODE_ENGINE */

  /* The fastpath object.  This field is set during initialization
     (before the first packet or interface callback), and remains constant
     until the engine is destroyed.  Thus, no locking is needed to access
     this field. */
  SshFastpath fastpath;

  SshFastpathFlowIDCB flow_id_hash;

  /* The number of CPU's in the system. */
  unsigned int num_cpus;

  /* An array of cpu specific contexts. */
  SshEngineCpuCtx cpu_ctx;
  SshKernelCriticalSectionStruct cpu_ctx_critical_section;

  /* Lock for protecting access to the flow table and transform
     records, as well as the rule table.  This lock is taken
     momentarily whenever accessing or modifying the flow table or
     transform records.  Whatever information is needed for processing
     the packet from the flow table or from the transform record is
     copied into the packet context so that this lock does not need to
     be kept during packet processing. */
  SshKernelMutex flow_control_table_lock;

  /* Lock for the packet context freelist. */
  SshKernelMutex pc_lock;

  /* Critical section for several tasks. E.g. for
     allocating packet contexts, allocating IP ID's. */
  SshKernelCriticalSectionStruct engine_critical_section[1];
  Boolean engine_critical_section_initialized;

  /* Lock for packets on engine->async_packets, engine->send_packets
     and engine->recursive_packets lists. */
  SshKernelMutex pp_lock;

#ifdef SSH_IPSEC_STATISTICS
  /* Global statistics counters. */
  SshEngineGlobalStatsStruct stats;
#endif /* SSH_IPSEC_STATISTICS */

  /* Lock for trigger rate limiting data (for triggers and for sending
     icmps).  This lock is only used when we are about to send a
     trigger to the policy manager (and in a related timeout which
     clears trigger blocking bits from the hash table bit vector), and
     when sending ICMPs. */
  SshKernelMutex trigger_lock;

  /* Lock for protecting the interface table. */
  SshKernelMutex interface_lock;

  /* Ports used for IKE and IKE NAT-T. These are set by the policy
     manager when it connects and whenever engine parameters are
     changed. No read locking performed. Updates covered by
     flow_control_table_lock. */
  SshUInt16 num_ike_ports;
  SshUInt16 local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];
  SshUInt16 local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];
  SshUInt16 remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];
  SshUInt16 remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];

  /* This is TRUE if policy lookups have been disabled by
     ssh_engine_pme_disable_policy_lookups, and FALSE if they are enabled. */
  Boolean policy_lookups_disabled;

  /* The packet interceptor object.  This field is set during
     initialization (before the first packet or interface callback),
     and remains constant until the engine is destroyed.  Thus, no
     locking is needed to access this field. */
  SshInterceptor interceptor;

  /* Back-pointer to the policy manager.  In the unified address space
     case this is the real policy manager object.  When engine and
     policy manager are at different address spaces, this is an opaque
     pointer, provided by the engine PM RPC implementation. */
  void *pm;

  /* A flag indicating whether the connection to the policy manager is
     currently open.  This field is protected by
     engine->flow_control_table_lock. */
  Boolean ipm_open;

  /* Engine flags from the ssh_engine_start() call. */
  SshUInt32 flags;

  /* Flags to be copied into packetcontext */
  SshUInt32 pc_flags;

  /* The minimum value required for a TTL in an IP header.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 min_ttl_value;

  /* Rate limit for all audit events in events/sec.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 audit_total_rate_limit;

  /* Current amount of events generated this second.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 audit_current_rate[SSH_ENGINE_NUM_AUDIT_LEVELS];

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Function to send messages to the policy manager.  This value is
     never changed after initialization, and need not be protected. */
  SshEngineSendProc send;

  /* Placeholder for machine-specific code.  This is passed when the
     engine is started, and is passed in any calls to
     platform-specific code (policy manager interface functions and
     interceptor functions).  An example of the use of this value is
     to contain the virtual router context in systems that implement
     multiple virtual routers in a single system (there appear to be
     several vendors working on this approach).  This value is never
     changed after initialization, and need not be protected. */
  void *machine_context;
#endif /* !SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /* A hashing and decision tree -based structure for finding matching
     rules. */
  SshEnginePolicyRuleSet policy_rule_set;

  /* Dummy default rules which will be used when no rule could be found. */
  SshEnginePolicyRule drop_rule;
  SshEnginePolicyRule pass_rule;
  SshEnginePolicyRule dhcp_ipv4_out_rule;
  SshEnginePolicyRule dhcp_ipv4_in_rule;
  SshEnginePolicyRule dhcp_ipv6_out_rule;
  SshEnginePolicyRule dhcp_ipv6_in_rule;

  /* A random value mixed to every flow id.  This should remain constant
     during the lifetime of the engine (actually, a policy manager connection
     to the engine).  This value should be unpredictable to an attacker.
     The purpose of this value is to allow the use of a relatively weak
     (but fast) hash function for computing the flow id while keeping the
     risk of an attacker being able to find conflicts in it low.  This value
     should come from the policy manager, since it has much better sources
     of randomness than the kernel. */
  SshUInt32 flow_id_salt[4];

  /* A PRNG */
#ifdef SSH_ENGINE_PRNG
  SshEngineRandomStateStruct prng;
#endif /* SSH_ENGINE_PRNG */

  /* Number of entries in the flow table. */
  SshUInt32 flow_table_size;

  /* NUmber of entries in the flow id hash table. */
  SshUInt32 flow_id_hash_size;

  /* Number of entries on the free flowlist */
  SshUInt32 num_free_flows;

  /* Flow control and data tables. Do not access this directly. Use
     the SSH_ENGINE_GET_FLOW(engine, index) macro. */
  SshEngineFlowControl *flow_control_table_root;

  /* Freelist for flow table entries. */
  SshUInt32 flow_table_freelist;

  /* Freelist for flow table entries (last_index). */
  SshUInt32 flow_table_freelist_last;

  /* List of doubly linked flows that are dangling due to either the
     forward or reverse transform being undefined. */
  SshUInt32 flows_dangling_list;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Size of the next hop table. */
  SshUInt32 next_hop_hash_size;

  /* Hash table for next hop nodes, hashed by next hop gw address.
     The size of this array is next_hop_hash_size. This field is
     protected by engine->flow_control_table_lock. */
  SshUInt32 *next_hop_addr_hash;

  /* Hash table for next hop nodes, hashed by ifnum. The size of this
     array is SSH_ENGINE_NH_C_IFNUM_HASH_SIZE. This field is protected
     by engine->flow_control_table_lock. */
  SshUInt32 *next_hop_ifnum_hash;

  /* Information for next hop gateways and hosts that we communicate with.
     The size of this array is next_hop_hash_size.  This field is protected
     by engine->flow_control_table_lock. */
  SshEngineNextHopControl *next_hop_control_table_root;

  /* Freelist for the next hop nodes.  This is SSH_IPSEC_INVALID_INDEX
     if the freelist is empty.  Nodes on the freelist are liked by the
     `next' field. */
  SshUInt32 next_hop_hash_freelist;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Size of the transform table. */
  SshUInt32 transform_table_size;

  /* Information about transforms to be performed on packets.  There is
     one entry in this table for each IKE Phase 2 SA (basically a
     bidirectional tunnel, which consists of at most four real IPSEC SAs
     and six SPIs: ESP in, AH in, IPCOMP in, ESP out, AH out, IPCOMP out).
     Entries in this table completely define the transformation to be
     performed on a packet per tunnel.  (For nested tunnels each level
     of nesting has a separate transform data object.)

     This field is protected by engine->flow_control_table_lock.  However,
     the lock should not be kept while actually processing the transform.
     Instead, if the flow indicates a transform, then the relevant fields
     of the transform record should be copied to local storage (into the
     packet processing context `pc', probably).  Replay prevention
     processing needs to be performed while this lock is held. */
  SshEngineTransformControl *transform_control_table_root;

  /* Freelist for transform nodes.  These have SSH_IPSEC_INVALID_INDEX
     if the freelist is empty.  Nodes that are on the freelist have
     the `transform' field set to zero and the `rules' field is the
     index of the next transform on the freelist. */
  SshUInt32 transform_table_freelist;
  SshUInt32 transform_table_freelist_tail;

  /* List of transform nodes waiting for destroy notification delivery
     to the policy manager.  Once the destroy notification is sent,
     these are queued to the transform node freelist.  These have
     SSH_IPSEC_INVALID_INDEX if the list is empty.  Nodes on the list
     have the `transform' field valid (as it used to be in the
     transform) and the `rules' field is the index of the next
     transform on the list. */
  SshUInt32 transform_destroy_notify_list;
  SshUInt32 transform_destroy_notify_list_tail;

  /* Hash table for transform record peers (the gw_addr field).  The size
     of this hash table is transform_table_size/8.  The value in this
     table is SSH_IPSEC_INVALID_INDEX if the hash slot is unused; otherwise
     it is the index of a transform record.  The hash list in the transform
     record slot is doubly linked to make deletion from the list efficient;
     the peer_next and peer_prev fields of the transform record are used to
     implement the list. */
  SshUInt32 *peer_hash;

  /* Hash table for transform record peer handles, i.e. the handle of the
     peer that created the transform. The size of this hash table is
     transform_table_size/8.  The value in this table is
     SSH_IPSEC_INVALID_INDEX if the hash slot is unused; otherwise it is
     the index of a transform record.  The hash list in the transform record
     slot is doubly linked to make deletion from the list efficient; the
     peer_handle_next and peer_handle_prev fields of the transform record are
     used to implement the list. */
  SshUInt32 *peer_handle_hash;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* List of transforms requiring NAT-T keepalive messages.  The
     keepalive list in the transform record slot is a doubly linked
     tomake deletion from the list efficient.  The
     `natt_keepalive_prev' and `natt_keepalive_next' fields of the
     transform record are used to implement the list. */
  SshUInt32 natt_keepalive;

  /* Interval in seconds how often NAT-T keepalive message timer is
     called. Value zero disabled sending of keepalive messages. */
  SshUInt32 natt_keepalive_interval;

  /* An IP address pool for the internal NAT.  The pool contains IPv4
     addresses from `internal_nat_first_ip' to `internal_nat_last_ip'.
     Note that the IP addresses are presented as 32 bit integers. */
  SshUInt32 internal_nat_first_ip;
  SshUInt32 internal_nat_last_ip;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Size of the rule table. */
  SshUInt32 rule_table_size;

  /* Array of available policy rule structures in the engine. */
  SshEnginePolicyRule *rule_table_root;

  /* Freelist for policy rules.  This is SSH_IPSEC_INVALID_INDEX if there are
     no rules on the freelist.  Rules on the freelist must be of type
     SSH_ENGINE_RULE_NONEXISTENT and are linked by the `param' field. */
  SshUInt32 rule_table_freelist;

  /* Table of packet context objects. */
  SshEnginePacketContext *pc_table_root;

  /* Freelist for packet contexts.  This field is protected by
     engine->pc_lock and consists on an array of ssh_kernel_num_cpus() + 1
     SshEnginePacketContext's.  */
  SshEnginePacketContext *pc_freelist;

#ifdef SSH_IPSEC_SEND_IS_SYNC
  /* Sending engine-generated packets asynchronously. */

  /* List of packets, queued for asynchronous invocations to
     ssh_engine_packet_send().  This field is protected by
     engine->pc_lock. */
  SshInterceptorPacket asynch_packets_head;
  SshInterceptorPacket asynch_packets_tail;

  /* Is a timeout scheduled for processing the list of asynchronous
     packets.  This field is proteced by engine->pc_lock. */
  Boolean asynch_timeout_scheduled;
#endif /* SSH_IPSEC_SEND_IS_SYNC */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Arp cache data structure. */
  SshEngineArpCacheStruct arp_cache;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /******************* Data for routing in the engine *********************/
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* Linked list of all routes registered in the engine.  The engine
     currently has a small fixed number of routes.  If at some point
     it is expected that the engine might have a large number of routes,
     then this must be changed into a proper routing data structure
     (for small configurations this kind of simple structure is desirable
     anyway). */
  SshEngineRouteStruct route_table[SSH_ENGINE_ROUTE_TABLE_SIZE];
#else /* SSH_IPSEC_INTERNAL_ROUTING */
  /* Number of route lookups currently active.  This is used to limit the
     maximum number of context objects that may be allocated from them. */
  SshUInt32 num_active_route_lookups;
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

  /******************* Data for periodic timeouts *************************/

  /* Timer value. This is "about" seconds since epoch. */
  SshTime run_time;

 /* Run time in microseconds. */
  SshUInt32 run_time_usec;

  /* How often each flow gets an event. */
  SshUInt32 age_full_seconds;

  /* The engine age callback is called every this many microseconds. */
  SshUInt32 age_callback_interval;

  /* Number of flows to check on every call to the age callback.
     This field is protected by engine->flow_control_table_lock. */
  SshUInt32 age_callback_flows;

  /* The number of transform events that can be sent the policy manager
     from one age timeout call. */
  SshUInt32 age_callback_trd_events;

  /* Index of the first flow to check on the next age callback.
     This field is protected by engine->flow_control_table_lock. */
  SshUInt32 age_callback_next;

  SshUInt8 age_timeout_repetitive : 1; /* Force use of repetitive flow timer */
  SshUInt8 age_callback_running : 1;   /* Age timeout callback running */
  SshUInt8 age_timeout_pkt_scheduled : 1; /* Age timeout (engine_timeout.c) has
                                             been scheduled packet driven. */

  SshTime age_timeout_sec;              /* Time of next age timeout. */
  SshUInt32 age_timeout_usec;

  /* Index of the first flow to check when looking for LRU flows.
     This field is protected by engine->flow_control_table_lock. */
  SshUInt32 flow_lru_next;

  /* Context data for age callback.  This temporary data is stored here
     to decrease stack usage. */
  SshEngineAgeCallbackContextStruct age_callback_context[1];

  /* Trigger context list.  Trigger events are sent from a timeout and the
     trigger contexts are stored here so that they can be freed properly
     when trigger timeouts are cancelled (during engine stop). */
  SshEngineTriggerContext trigger_context;

  /******************** Data for trigger rate limiting *******************/

  /* Bitmap for limiting the rate of trigger messages sent for the same or
     similar packets.  The first half is used for normal triggers, and the
     second half for crash recovery triggers.  This is protected by the
     engine->trigger_lock. */
  SshUInt32 trigger_bitmap[2 * SSH_TRIGGER_BITMAP_WORDS];

  /* Flag indicating that at least one bit in the trigger bitmap is non-zero.
     This also indicates that a timeout has been scheduled to clear the
     bitmap.  This is protected by the engine->trigger_lock. */
  Boolean trigger_sent;

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Number of pending policy manager upcall timeouts. */
  SshInt32 num_pending_upcall_timeouts;

  /* True if the engine has been stopped but there were active trigger
     timeouts in the system.  The trigger timeout checks this flag and
     if it is set and the timeout is the last pending timeout, it must
     free the engine. */
  Boolean stopped;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /********************* Data for IP processing ***************************/

  /* Array of (engine->num_cpus) values for the id field of the next
     packet to be sent (initiated) by the engine on the current CPU. This
     is also used to generate ID's for tunneled packets. */
  SshUInt16 *next_packet_id;

  /* Bitmap for limiting the rate of ICMP messages of a particular type to
     send to about one per second.  Access to this field should be
     protected by the engine->trigger_lock. */
  SshUInt32 response_rate_bitmap[(SSH_ICMP_BITMAP_SIZE + 31) / 32];

  /* Flag indicating that ssh_engine_response_rate_limit_clear()
     timeout has been scheduled and at least one bit is
     set in response_rate_bitmap.
     Access to this field should be protected by the
     engine->trigger_lock. */
  Boolean rate_timeout_scheduled;

  /* Flag indicating that ssh_engine_flow_rate_decrement()
     has been scheduled. */
  Boolean flow_rate_timeout_scheduled;

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  /* Bitmap for limiting flows */
  SshUInt32 flow_rate_hash[SSH_ENGINE_FLOW_RATE_HASH_SIZE];

  /* Total values in the above hash */
  SshUInt32 flow_rate_total;

  /* The maximum amount of flow creates a single slot in the flow rate
     limitation table is allowed to own without it ever being considered
     for rate limitation.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 flow_rate_allow_threshold;

  /* The maximum amount of flow creates a second allowed from a slot
     in the limitation table. Any more than this and the flow
     creates will always be rate limited.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 flow_rate_max_threshold;

  /* Rate limitation in percentages. If more than this
     threshold of max flows are in use, then the rate limitation
     below will be used.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 flow_rate_limit_threshold;

  /* The amount of flow creates over the total requested that
     is allowed from a single hash slot.
     Protected by engine->flow_control_table_lock. */
  SshUInt32 flow_rate_max_share;
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  /* Idle timeout for IPSec transforms. After this number of seconds
     a idle event for that transform will be sent to the policy manager if
     DPP is enabled for that transform. This event will trigger a DPD
     negotiation at the policy manager. */
  SshUInt32 transform_dpd_timeout;

  /*************** Information for Port NAT *********************/

#ifdef SSHDIST_IPSEC_NAT
  /* Table of Port NAT objects. */
  SshEngineNatPort *nat_port_table_root;

  /* Freelist for port NAT entries. This is NULL if there are no entries on
     the freelist. Entries on the freelist are linked by the `next' field. */
  SshEngineNatPort nat_port_freelist;

  /* Hash table of in-use port NAT objects */
  SshEngineNatPort *nat_ports_hash;

  /* NAT target ports for normal
     source ports (1024-65535 and 0) */
  SshUInt16 nat_normal_low_port;
  SshUInt16 nat_normal_high_port;
  /* NAT target ports for privileged
     source ports (1-1023) */
  SshUInt16 nat_privileged_low_port;
  SshUInt16 nat_privileged_high_port;
#endif /* SSHDIST_IPSEC_NAT */

  /*************** Copy of last interface information ***********/

  /* Structure containing the interface list. Protected
     by 'engine->flow_control_table_lock'. */
  SshIpInterfacesStruct ifs;

  /**************** Misc flags **********************************/

  SshUInt8 undangle_all_pending : 1;   /* Call undangle_all from engine
                                          timeout. Protected by
                                          engine->flow_control_table_lock */

  SshUInt8 optimize_routing : 1;       /* Use interface tables for
                                          routing decisions also. Protected by
                                          engine->flow_control_table_lock */

  SshUInt8 drop_if_cannot_audit : 1;   /* Drop a packet if an auditable
                                          event which a packet generates
                                          cannot be audited. Protected by
                                          engine->flow_control_table_lock */

  SshUInt8 broadcast_icmp : 1;         /* Drop all the icmp broadcast
                                          packets */

  /*------------------------------------------------------------------*/
  /* Timeout flags; non repetive timer system                         */
  /*------------------------------------------------------------------*/

  SshUInt8 audit_timeout_scheduled : 1;/* Engine has scheduled timeout to
                                          notify policy manager that there
                                          are audit events available to be
                                          polled. See
                                           SSH_PM_AUDIT_REQUESTS_PER_SECOND */

  /* Data for pending audit events. Protected by the flow_control_table_lock */
  SshUInt32 audit_flags;
  SshUInt32 audit_event_id;
  SshUInt32 audit_table_size; /* Each audit table has the same size. */
  SshUInt32 audit_table_head[SSH_ENGINE_NUM_AUDIT_LEVELS];
  SshUInt32 audit_table_tail[SSH_ENGINE_NUM_AUDIT_LEVELS];
  SshEngineAuditEvent audit_table[SSH_ENGINE_NUM_AUDIT_LEVELS];

#ifdef SSH_IPSEC_TCPENCAP
  /* Lock for protecting encapsulating TCP connection entries
     and configuration data. */
  SshKernelMutex tcp_encaps_lock;
  SshEngineTcpEncapsConn *tcp_encaps_connection_table;
  SshEngineTcpEncapsConfig tcp_encaps_configuration_table;

  /* Initial timeout and negotiation timeout lists. */
  SshEngineTcpEncapsConn tcp_encaps_initial_timeout_list;
  SshEngineTcpEncapsConn tcp_encaps_negotiation_timeout_list;

  /* Timestamp of next scheduled timeout. */
  SshTime tcp_encaps_timeout_sec;
  SshUInt32 tcp_encaps_timeout_usec;

  /* Protected by 'flow_control_table' lock. */
  SshEngineTcpEncapsDelete tcp_encaps_delete_list;
#endif /* SSH_IPSEC_TCPENCAP */




} SshEngineStruct;



#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
/* Context structure for passing control from the engine to
   the policymanager thread via a zero-timeout. */
typedef struct SshEngineFlowNotificationRec
{
  /* Engine the flow notification corresponds to */
  SshEngine engine;

  /* Index of the flow which was destroyed */
  SshUInt32 flow_index;

  /* Timeout struct for the call */
  SshTimeoutStruct tmout_struct;
} *SshEngineFlowNotification, SshEngineFlowNotficationStruct;

Boolean
ssh_engine_upcall_timeout(SshEngine engine);

#ifdef USERMODE_ENGINE
/* This function is used to set the runtime context such that it
   corresponds with kernel mode execution in a unified-usermode
   AND usermode build. Currently this is used for tuning the
   stack size. */
void
ssh_engine_pme_set_context_kernel(SshEngine engine);

/* This function is used to set the runtime context such that it
   corresponds with  usermode mode execution in a unified-usermode
   AND usermode build. Currently this is used for tuning the
   stack size. */
void
ssh_engine_pme_set_context_usermode(SshEngine engine);
#endif /* USERMODE_ENGINE */

void
ssh_engine_record_upcall(SshEngine engine);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

/* Return the greatest LRU level of flows which can be reaped
   to make space in the flow table for flows associated
   with the rule with index 'rule_index'. */
int
ssh_engine_flow_reap_lru_level(SshEngine engine,
                               SshUInt32 rule_index);


/* Free flows of LRU level 'lru_level' until at least 'nflows' are
   free in the flow table.  'nflows' must be less than
   SSH_ENGINE_MAX_REAP_FLOWS. Return TRUE if succesful.

   If FALSE is returned, then no flows have been reaped. */
#define SSH_ENGINE_MAX_REAP_FLOWS 10
Boolean
ssh_engine_reap_flows(SshEngine engine, int lru_level, size_t nflows);

/* The ssh_engine_flow_is_no_flow() functions returns TRUE, if
   the flow parameters are such, that a flow creation can not
   be supported. This gives the rule execution state machine a hint
   that the packet may be handled as a no-flow packet IF acceptable
   (no NAT, etc..) */
Boolean
ssh_engine_flow_is_no_flow(SshUInt8 ipproto, SshUInt16 dst_port);

/* Creates and initializes a new flow table node, and adds it to the
   flow hash table (both forward and reverse lists).  `rule_index' is
   the rule that caused this flow to be created; it can be
   SSH_IPSEC_INVALID_INDEX, in which case the flow is not associated
   with any rule (as is the case with IPSEC inbound flows).  `flags'
   is the initial flags for the node (0 for normal nodes,
   SSH_ENGINE_FLOW_IPSECINCOMING for incoming IPSEC flows).  This
   returns the index of the node in `*flow_index_return'. The flow
   index returned is of the form SSH_ENGINE_FLOW_WRAP_INDEX(flow->generation,
   flow_index), so it must be unwrapped using SSH_ENGINE_FLOW_UNWRAP_INDEX
   for use. This returns TRUE on success, and FALSE if the flow could
   be allocated (for example, the flow table is full).  If `forward_nh_index'
   and/or `reverse_nh_index' are set, they must already have a
   reference counted for each of them.  If `forward_transform_index'
   and/or `reverse_transform_index' is set, then this increments the
   reference count of the transform if successful.
   Engine->flow_control_table_lock must be held when this is called.
   If the flow is an ICMP flow, then ssh_engine_create_flow()
   expects the ICMP type/code fields to be in 'dst_port'
   as "(type << 8) | code". */
Boolean ssh_engine_create_flow(SshEngine engine,
                               SshUInt32 rule_index,
                               const unsigned char *forward_flow_id,
                               SshIpAddr src_ip,
                               SshIpAddr dst_ip,
                               SshUInt8 ipproto,
                               SshUInt16 src_port,
                               SshUInt16 dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                               SshUInt32 ifnum_dst,
                               SshUInt32 ifnum_src,
                               Boolean local_dst,
                               Boolean local_src,
                               SshUInt16 mtu_dst,
                               SshUInt16 mtu_src,
                               SshUInt32 route_selector_dst,
                               SshUInt32 route_selector_src,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                               SshUInt32 forward_nh_index,
                               SshUInt32 reverse_nh_index,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                               SshEngineIfnum incoming_forward_ifnum,
                               SshEngineIfnum incoming_reverse_ifnum,
#ifdef SSHDIST_IPSEC_NAT
                               const SshIpAddr nat_src,
                               const SshIpAddr nat_dst,
                               SshUInt16 nat_src_port,
                               SshUInt16 nat_dst_port,
#endif /* SSHDIST_IPSEC_NAT */
                               SshUInt32 protocol_xid,
                               SshUInt16 c_flags,
                               SshUInt32 d_flags,
                               SshUInt32 forward_transform_index,
                               SshUInt32 reverse_transform_index,
                               SshUInt32 idle_timeout,
                               SshUInt32 max_lifetime,
                               SshVriId routing_instance_id,
                               SshUInt32 *extension,
                               SshUInt32 *flow_index_return);

/* Creates an incoming IPSEC flow for the rule index.  This returns
   the flow index of the new flow, or SSH_IPSEC_INVALID_INDEX if it could
   not be created (e.g., flow table was full).  Engine->flow_control_table_lock
   must be held when this is called. */
SshUInt32 ssh_engine_create_incoming_ipsec_flow(SshEngine engine,
                                                SshUInt32 rule_index,
                                                SshUInt32 life_seconds);

/* Frees the given flow and any associated flow id hash and next hop nodes,
   as well as any associated flow table nodes (in the case of IPSEC SAs).
   This must be called with engine->flow_control_table_lock held.
   This function accepts also wrapped flow_indices. */
void ssh_engine_free_flow(SshEngine engine, SshUInt32 flow_index);

/* This function places a flow on the 'dangling' list. The flow
   MUST NOT already be 'dangling'. The flow is attached to a
   suitable rule (TRIGGER or PASS) if one is found, if not
   ssh_engine_flow_dangle() returns FALSE and the flow should
   be destroyed. All transforms are detached from the flow
   and forward_transform_index/reverse_transform_index are used
   for other purposes while the flow is dangling. The
   flow is removed from the reverse_flow_hash. IPsec incoming
   flows cannot be dangled (they result in a return value of FALSE).
   'engine->flow_control_table_lock' must be held during this call. */
Boolean
ssh_engine_flow_dangle(SshEngine engine, SshUInt32 flow_index);

/* This function undangles a dangling flow. The flow MUST be dangling.
   If the undangle operation failed due to problems with inconsistent
   state in the engine, the function returns SSH_ENGINE_FLOW_STATUS_ERROR,
   and the flow should be destroyed. If the engine policy does not
   currently allow for the flow to be undangled, then it will return
   SSH_ENGINE_FLOW_STATUS_DANGLING, and the flow is still dangling.
   If the policy and state allow for the flow to be undangled,
   then the flow will be attached to a suitable rule (as specified
   by policy) and acceptable forward and reverse transforms, flow
   id's will be recomputed and the flow will be placed in the
   flow id hash tables. In this case SSH_ENGINE_FLOW_STATUS_WELL_DEFINED
   will be returned.
   'engine->flow_control_table_lock' must be held during this call. */

typedef enum {
  /* Flow cannot be well defined anymore due to incomplete state in the
     engine. */
  SSH_ENGINE_FLOW_STATUS_ERROR,

  /* Flow is fully well defined. */
  SSH_ENGINE_FLOW_STATUS_WELL_DEFINED,

  /* Flow is not well defined. Associated with TRIGGER rule. */
  SSH_ENGINE_FLOW_STATUS_DANGLING,

  /* The flow requires a generation of a reverse trigger, for it
     to be ever undangled. It is still dangling. */
  SSH_ENGINE_FLOW_STATUS_REVERSE_TRIGGER
} SshEngineFlowStatus;

SshEngineFlowStatus
ssh_engine_flow_undangle(SshEngine engine, SshUInt32 flow_index);

/* The ssh_engine_flow_undangle_all() function attempts to undangle
   all flows in the engine, that are dangling. This function
   grabs 'engine->flow_control_table_lock' during it's execution, so it
   MUST NOT be held prior to call. */
void
ssh_engine_flow_undangle_all(SshEngine engine);

/* The ssh_engine_flow_compute_flow_id_from_flow() function
   attempts to compute the flow id of a flow that corresponds
   to the current flow parameters. If 'is_forward' is TRUE, then
   the forward flow id is computed. If 'is_forward' is FALSE, then
   the reverse flow id is computed. The result is placed in the
   buffer 'flow_id'. If the engine state does not allow for
   computation of the flow id, then FALSE is returned. */
Boolean
ssh_engine_flow_compute_flow_id_from_flow(SshEngine engine,
                                          SshUInt32 flow_index,
                                          SshEngineFlowData d_flow,
                                          Boolean is_forward,
                                          unsigned char *flow_id);


/* Reset a flow<->trd association for either the
   forward or reverse transform. This sets either
   flow->forward_transform_index or flow->reverse_transform_index
   to SSH_IPSEC_INVALID_INDEX. engine->flow_control_table_lock
   must be held during the function call. If is_forward == FALSE,
   then flow->rule_index MUST still be valid. */
void
ssh_engine_flow_reset_trd(SshEngine engine,
                          SshUInt32 flow_index,
                          SshEngineFlowData d_flow,
                          Boolean is_forward);

/* Set either the forward or reverse transform index for a flow.
   The relevant transform index must be SSH_IPSEC_INVALID_INDEX
   at the time of call (e.g. reset using ssh_engine_flow_reset_trd()).
   engine->flow_control_table_lock must be held during the call.
   flow->rule_index MUST be valid during the call. */
void
ssh_engine_flow_set_trd(SshEngine engine, SshUInt32 flow_index,
                        SshEngineFlowData d_flow,
                        Boolean is_forward, SshUInt32 new_trd_idx);

/* Reset the flow->rule association. Engine->flow_control_table_lock
   MUST be held during the call. Flow->forward_transform_index
   MUST be consistent with flow->rule->transform_index during
   the call. */
void
ssh_engine_flow_reset_rule(SshEngine engine, SshUInt32 flow_index);

/* Set flow->rule association. Engine->flow_control_table_lock MUST
   be held during the call. */
void
ssh_engine_flow_set_rule(SshEngine engine, SshUInt32 flow_index,
                         SshUInt32 rule_idx);

/* Find a rule for the reverse_transform_index of flow 'flow', assuming
   that 'flow->rule_index' defines the forward_transform_index.
   The result is placed in *result, with the return value denoting
   success or failure. The assumption is that 'flow->rule_index'
   and the rule it references are defined, as are the other
   flow parameters (src_ip, dst_ip, etc..) and forward_transform_index,
   but not reverse_transform_index. The lock 'engine->flow_control_table_lock'
   must be held during the call. */
Boolean
ssh_engine_flow_find_reverse_rule(SshEngine engine,
                                  SshUInt32 flow_index,
                                  SshEnginePolicyRule transform_rule,
                                  SshUInt32 *result);

/* Find a rule that is equal to 'pm_rule' parameter. The
   'engine->flow_control_table_lock' must be held during this call. The
   function returns NULL if it cannot find a suitable rule. The
   purpose of this function is to cache elements in the
   rule lookup prior to their use. */
SshEnginePolicyRule
ssh_engine_find_equal_rule(SshEngine engine,
                           const SshEnginePolicyRule pm_rule);

SshEnginePolicyRule
ssh_engine_find_equal_rekey_rule(SshEngine engine,
                                 const SshEnginePolicyRule pm_rule);


/* If flow_index is an APPGW flow, then attempt to find a suitable
   rule for which SSH_PM_ENGINE_RULE_UNDEFINED is unset and which
   specifies the 'transform_index' for the appgw<->responder flow.
   'engine->flow_control_table_lock' must be held during this call. */

#define SSH_ENGINE_ATT_MATCH_UNUSED   0x0001  /* match unused use once rules */
SshUInt32
ssh_engine_find_appgw_totunnel_rule(SshEngine engine, SshUInt32 flow_index,
                                    SshUInt32 flags);

/* Generate a IP identification used when contructing IPv4 headers.
   IP ID is incremented from it's previous value on the same CPU. */
SshUInt16 ssh_engine_get_ip_id(SshEngine engine);

/* Generate a IPv6 fragment identification value used when fragmenting
   an IPv6 datagram. IPv6 fragment ID is incremented from it's previous
   value. */
SshUInt32 fastpath_get_ipv6_frag_id(SshFastpath fastpath);

/**********************************************************************
 * Statistics-related stuff.
 **********************************************************************/

/* Mark that the statistics counter counter_id should be incremented.  The id
   may refer to either a per-flow or a global counter. */
#ifdef SSH_IPSEC_STATISTICS
#define SSH_ENGINE_MARK_STAT(pc, counter_id) \
  (pc)->stat_vec[(counter_id) / 32] |= (1 << ((counter_id) & 31))
#else /* SSH_IPSEC_STATISTICS */
#define SSH_ENGINE_MARK_STAT(pc, counter_id)
#endif /* SSH_IPSEC_STATISTICS */

/**********************************************************************
 * Routing-related functions.
 **********************************************************************/

/* Callback function that is called when ssh_engine_route completes.
   `flags' is information about the found route;
   SSH_PME_ROUTE_REACHABLE indicates that a route was found for the
   destination (otherwise all other data is invalid).  `dst' is the
   original destination used in the call to ssh_engine_route (it is
   valid even if the route is not reachable), `next_hop_gw' is the
   next hop gateway (same address as dst if SSH_PME_ROUTE_LOCAL or
   SSH_PME_ROUTE_LOCALNET is supplied), `ifnum' is the interface
   through which the packets should be sent, and `mtu' is the link MTU
   for the interface (or path MTU for `dst' if known, but this cannot
   be depended on).  `context' is the context argument supplied in the
   call to ssh_engine_route. */
typedef void (*SshEngineRouteCB)(SshEngine engine,
                                 SshUInt32 flags,
                                 const SshIpAddr dst,
                                 const SshIpAddr next_hop_gw,
                                 SshEngineIfnum ifnum,
                                 SshVriId routing_instance_id,
                                 size_t mtu,
                                 void *context);

/* Fills in SshInterceptorRouteKey 'key' with values given as parameters
   'src', 'dst', 'ipproto', 'src_port', 'dst_port', 'spi', and 'ifnum'.
   The parameter 'outgoing' specifies, whether 'ifnum' denotes the outbound
   interface number, or the inbound interface number. Other selectors are
   extracted from the packet context 'pc'.

   Parameter `transform_applied' specifies whether the engine is transforming
   packets that go to this destination. If set to TRUE, then the packets might
   be larger than the path MTU reported to the IP stack by the engine.

   This function will check if 'src' or 'dst' are local addresses. 'dst'
   must be a valid IP address. 'src' may be an undefined SshIpAddr or NULL,
   in which case the source address selector will not be set in the routing
   key. If 'src' is a multicast or broadcast address, then it will be
   replaced by the local IP address of the interface 'ifnum'. */
void ssh_engine_create_route_key(SshEngine engine,
                                 SshInterceptorRouteKey key,
                                 SshEnginePacketContext pc,
                                 SshIpAddr src,
                                 SshIpAddr dst,
                                 SshUInt8 ipproto,
                                 SshUInt16 src_port,
                                 SshUInt16 dst_port,
                                 SshUInt32 spi,
                                 SshEngineIfnum ifnum,
                                 SshUInt32 route_flags,
                                 SshUInt32 *extension,
                                 SshVriId routing_instance_id);

/* Performs routing for the given routing key `key'.  The argument
   `flags' specifies optional arguments for the route operation.  See
   ssh_pme_route() for the details.  The argument `outgoing' specifies
   whether the destination address is routed for an outgoing or an
   incoming packet.  The argument `packet_ifnum' is the interface from
   which the currently processed packet was received.  It is used as
   the `ifnum' argument of the SshEngineRouteCB for broadcast
   destination addresses.  The `packet_ifnum' argument is ignored for
   unicast destination addresses.  This calls `callback' either during
   this call or at some later time.  The results of the route lookup
   are passed to the callback.  It is guaranteed that this handles
   local interface addresses, directed broadcasts, and hosts on local
   subnets correctly (setting the appropriate flag bits).  Other hosts
   are routed according to the routing information, either in the
   engine internal routing tables (if SSH_IPSEC_INTERNAL_ROUTING is
   defined) or (otherwise) in system tables. */
void ssh_engine_route(SshEngine engine,
                      SshUInt32 flags,
                      SshInterceptorRouteKey key,
                      Boolean outgoing,
                      SshEngineRouteCB callback,
                      void *context);

#ifdef SSH_IPSEC_INTERNAL_ROUTING
/* Adds a new route to the engine internal routing table.  The route does
   not automatically get added to system routing tables.  If a route already
   exists for the same `dst_and_mask', then the new route overrides the
   old route.  This returns TRUE if the route was successfully added, and
   FALSE if it could not be added (e.g., routing table full). */
Boolean ssh_engine_route_add(SshEngine engine,
                             const SshIpAddr dst_and_mask,
                             const SshIpAddr next_hop,
                             SshUInt32 ifnum);

/* Removes the given route from the engine internal routing table.  This does
   not automatically modify system routing tables.  This returns TRUE
   if the route was found and deleted, and FALSE if the route did not exist
   in the engine routing table. */
Boolean ssh_engine_route_remove(SshEngine engine,
                                const SshIpAddr dst_and_mask);

#endif /* SSH_IPSEC_INTERNAL_ROUTING */

/* This callback may get called by the interceptor whenever routing
   information changes or from ssh_engine_pme_redo_flows(). However,
   sending these callbacks is optional, and the engine will also
   otherwise periodically update cached information.  This function can
   get called concurrently with other functions. It expects to receive
   the engine pointer as context.
   The function initiates an asynchronous iteration over all flows,
   that updates the routing information in each flow, re-evaluates
   the policy rule for the flow, sets/clears any tunneling as required
   by new rule, and finally re-computes flow-ids. The flow may be left
   dangling. */
void ssh_engine_route_change_callback(void *context);

/* Returns TRUE if the given address is a local IP address of this
   host, and FALSE otherwise. */
Boolean ssh_engine_ip_is_local(SshEngine engine, const SshIpAddr dst);

/* Returns TRUE if the given address is link broadcast, directed
   subnet broadcast or multicast addresses e.g. if the destination
   address is a valid broadcast address to this host, the function
   returns TRUE. */
Boolean ssh_engine_ip_is_broadcast(SshEngine engine, const SshIpAddr dst);

/**********************************************************************
 * Policy rule related stuff.  This code is mostly implemented in
 * engine_rules.c, engine_rule_lookup.c, and engine_rule_execute.c.
 **********************************************************************/

/* Initialize the engine's policy rule lookup mechanism.  Return TRUE
   if successful, otherwise FALSE. */
SshEnginePolicyRuleSet ssh_engine_rule_lookup_allocate(SshEngine engine);

/* Dispose of the engine's policy rule lookup mechanism.  This does
   not free the rules themselves, only the internal data structures of
   the lookup mechanism.  Returns TRUE on success. */
Boolean ssh_engine_rule_lookup_dispose(SshEngine engine,
                                       SshEnginePolicyRuleSet rs);

/* This looks up the highest precedence policy rule that matches the
   given input paramrters. This returns the best matching rule, or NULL
   if no matching rule is found.  If several matching rules are found
   at the same precedence, one of them is picked arbitrarily by this
   function.  Engine->flow_control_table_lock must be held when this is
   called. */
SshEnginePolicyRule
ssh_engine_rule_lookup(SshEngine engine,
                       SshEnginePolicyRuleSet rs,
                       const unsigned char *src_ip,
                       const unsigned char *dst_ip,
                       size_t addr_len,
                       SshInetIPProtocolID ipproto,
                       SshUInt16 src_port, SshUInt16 dst_port,
                       SshEnginePacketContext pc);

/* A generic interface for looking up rules.  Return a matching rule
   with the highest precedence, or NULL if not found.

   `src_ip' and `dst_ip' are the source and destination ip numbers,
   correspondingly, and `ip_addr_len' must be the number of bytes in
   the `src_ip' and `dst_ip', i.e. either 4 for IPv4 or 16 for IPv6.
   `SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS' of this packet's
   extension values.  If `extensions' is NULL, then the extensions are
   ignored.

   `test_fun' is a function which tests whether the given rule
   satisfies the conditions.  `test_fun' may assume that the ip and
   port numbers in the suggested rule match, but because of a distinct
   possibility of hash collisions, it may *not* assume that the values
   used for `flag_hash' match.  If `test_fun' is NULL, then it is
   assumed to return TRUE regardless of the rule.  `ctx' is passed as
   a second argument to `test_fun'.

   engine->flow_control_table_lock must be held when this is called. */

typedef Boolean (*SshEnginePolicyRuleTestFun)(SshEngine engine,
                                              SshEngineLookupPreamble rule,
                                              const SshUInt32 *extensions,
                                              void *ctx);

SshEngineLookupPreamble
ssh_engine_rule_generic_lookup(SshEngine engine,
                               SshEnginePolicyRuleSet rs,
                               const unsigned char src_ip[16],
                               const unsigned char dst_ip[16],
                               size_t ip_addr_len,
                               SshUInt32 tunnel_id,
                               SshUInt16 src_port, SshUInt16 dst_port,
                               const SshUInt32 *extensions,
                               SshEnginePolicyRuleTestFun test_fun,
                               void *ctx);

/* Utility function for looking up a rule, which would create the
   flow 'flow_idx' against the current policy. */
SshEnginePolicyRule
ssh_engine_find_flow_rule(SshEngine engine, SshUInt32 flow_idx);


/* Utility function for looking up a rule index for a SSH_ENGINE_RULE_APPLY
   rule, which should have selectors matching the parameters. Return
   a valid rule index if found. Otherwise return SSH_IPSEC_INVALID_INDEX.
   See the documentation for ssh_engine_pme_find_transform_rule(). */
SshUInt32
ssh_engine_find_transform_rule(SshEngine engine,
                               SshUInt32 tunnel_id,
                               SshUInt32 ifnum,
                               const SshIpAddr src_ip,
                               const SshIpAddr dst_ip,
                               SshUInt8 ipproto,
                               SshUInt16 src_port,
                               SshUInt16 dst_port,
                               SshUInt32 impl_tunnel_id,
                               SshUInt32 trd_index,
                               unsigned char *peer_id,
                               SshUInt32 flags);

/* Allocates a policy rule object.  Returns the index of the new rule,
   or SSH_IPSEC_INVALID_INDEX if no more rule objects are available.
   Engine->flow_control_table_lock must be held when this is called. */
SshUInt32 ssh_engine_rule_allocate(SshEngine engine);

/* Frees a policy rule object.  Engine->flow_control_table_lock must be
   held when this is called. */
void ssh_engine_rule_free(SshEngine engine, SshUInt32 rule_index);

/* The rule lookup uses unused selector fields for it's own purposes.
   These fields are initialized per the rule contents in this
   function. */
void
ssh_engine_rule_lookup_prepare(SshEngine engine,
                               SshEnginePolicyRuleSet rs,
                               SshEngineLookupPreamble rule);

/* Force rebuild of rule lookup data structures. Flow table lock must
   be held when this function is called. This may be an expensive
   operation, and should only be performed when the policy changes. */
void
ssh_engine_rule_lookup_flush(SshEngine engine, SshEnginePolicyRuleSet rs);

/* Adds the rule to the data structures used for rule lookups.
   This returns TRUE if the rule was successfully added, and FALSE if an
   error occurs.
   engine->flow_control_table_lock must already be held when this is called. */
Boolean ssh_engine_rule_lookup_add(SshEngine engine,
                                   SshEnginePolicyRuleSet rs,
                                   SshEngineLookupPreamble rule);

/* Removes the rule from the data structures used for rule lookups.
   engine->flow_control_table_lock must already be held when this is called. */
void ssh_engine_rule_lookup_remove(SshEngine engine,
                                   SshEnginePolicyRuleSet rs,
                                   SshEngineLookupPreamble rule);

#ifdef DEBUG_LIGHT
/* Checks that the rule is not present in the policy lookup data
   structures.  It is a fatal error if it is.
   engine->flow_control_table_lock must be held when this is called. */
void ssh_engine_rule_lookup_assert_not_there(SshEngine engine,
                                             SshEnginePolicyRuleSet rs,
                                             SshEngineLookupPreamble rule);
#endif /* DEBUG_LIGHT */

/* This functions is called during policy decisions when we have found a
   matching rule.  This function excutes the rule - this either processes
   the packet immediately or creates a flow.  This may also start an
   asynchronous process (possibly involving the policy manager)
   e.g. to negotiate new security associations.  This returns
   SSH_ENGINE_RET_ASYNC if an asynchronous operation was started,
   SSH_ENGINE_RET_ERROR if an error caused pc->pp to become invalid, and
   can return other values of the type SshEngineActionRet. */
SshEngineActionRet ssh_engine_execute_rule(SshEnginePacketContext pc);

/* This function is called to refresh next hop information of a flow. */
SshEngineActionRet ssh_engine_reroute_flow(SshEnginePacketContext pc);

/* Decrements the reference count of the given rule, and if it becomes
   zero, frees the rule. */
void ssh_engine_decrement_rule_refcnt(SshEngine engine,
                                      SshEnginePolicyRule rule);

/* Deletes the specified rule and all of its flows and dependent
   rules.  This may also delete trds if they have no more references.
   Engine->flow_control_table_lock must be held when this is called. */
void ssh_engine_delete_rule(SshEngine engine, SshUInt32 rule_index);

#ifdef SSHDIST_IPSEC_NAT
/**********************************************************************
 * Creating and manipulating NAT domains.
 **********************************************************************/

/* Returns different unused <ip:port> pairs on the interfaces src_ifnum
   and dst_ifnum. If src_ip or dst_ip is defined, then a port on
   that IP is provided, if not then any IP attached to the
   specified interface is used, the 'is_ipv6' parameter specifies which
   address type to search for on the interface..

   If src_port is unset (0), src_port_orig can be used to indicate
   original port number, which is used to determine whether to do
   privileged or unprivileged NAT mapping.

   If nat_src_ip_return or nat_dst_ip_return is NULL, then a corresponding
   <ip:port> pair is obviously not searched for or returned.

   Engine->flow_control_table_lock must be held when this is called.

   If no suitable <ip:port> pairs can be found, then FALSE is returned,
   otherwise ssh_engine_nat_get_unused_map() returns TRUE. */
Boolean ssh_engine_nat_get_unused_map(SshEngine engine,
                                      Boolean is_ipv6,
                                      SshEngineIfnum src_ifnum,
                                      const SshIpAddr src_ip,
                                      const SshIpAddr src_ip_orig,
                                      SshUInt16 src_port,
                                      SshUInt16 src_port_orig,
                                      SshEngineIfnum dst_ifnum,
                                      const SshIpAddr dst_ip,
                                      SshUInt16 dst_port,
                                      SshIpAddr nat_src_ip_return,
                                      SshUInt16 *nat_src_port_return,
                                      SshIpAddr nat_dst_ip_return,
                                      SshUInt16 *nat_dst_port_return);

/* ssh_engine_nat_get_mapping() returns a currently unused NAT mapping
   for a flow with the parameters provided.

   This returns zero if nothing was done, or the logical or of
   SSH_ENGINE_FLOW_D_NAT_SRC and/or SSH_ENGINE_FLOW_D_NAT_DST.  If an
   error occurs (and the packet should be dropped), this returns
   0xffffffff.

   The `ipproto' argument specifies the IP protocol of the packet for
   which translation is being looked up (TCP, UDP, or ICMP ECHO).  The
   `type' argument specifies what kind of NAT should be performed.

   The `{src,dst}_{ip,port}' arguments specify the current source and
   destination addresses of the packet, and are modified by this function
   to the after-NAT values if NAT should be performed. The nat_*_out
   parameters provide pointers to storage where to place return values.

   Engine->flow_control_table_lock must be held when this is called. */
SshUInt16 ssh_engine_nat_get_mapping(SshEngine engine,
                                     SshUInt32 flags,
                                     SshUInt8 ipproto,
                                     SshUInt8 icmp_type,
                                     Boolean outbound,
                                     SshEngineIfnum ifnum_src,
                                     SshEngineIfnum ifnum_d1st,
                                     const SshIpAddr src_ip,
                                     const SshIpAddr dst_ip,
                                     SshUInt16 src_port,
                                     SshUInt16 dst_port,
                                     SshIpAddr nat_src_ip_out,
                                     SshUInt16 *nat_src_port_out,
                                     SshIpAddr nat_dst_ip_out,
                                     SshUInt16 *nat_dst_port_out);

/* Returns different unused <ip:port> pair on the interfaces ifnum.
   If ip is defined, then a port on that IP is provided, if not then any
   IP attached to the specified interface is used, the 'is_ipv6' parameter
   specifies which address type to search for on the interface..

   If src_port is unset (0), src_port_orig can be used to indicate
   original port number, which is used to determine whether to do
   privileged or unprivileged NAT mapping.

   Engine->flow_control_table_lock must be held when this is called.

   If no suitable <ip:port> pair can be found, then FALSE is returned,
   otherwise ssh_engine_get_random_port() returns TRUE.

   This is similar to ssh_engine_nat_get_unused_map, but only handles
   one traffic direction at once. */
Boolean
ssh_engine_get_random_port(SshEngine engine,
                           Boolean get_free_port,
                           Boolean is_ipv6,
                           SshEngineIfnum ifnum,
                           const SshIpAddr ip_in,
                           const SshIpAddr ip_orig,
                           SshUInt16 port_in,
                           SshUInt16 port_orig,
                           const SshIpAddr ip_forbid,
                           SshUInt16 port_forbid,
                           SshIpAddr ip_return,
                           SshUInt16 *port_return);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/* Tries to allocate an IP address from the internal NAT pool.  The
   function returns the allocated IP adddress in `ip_return'.  The
   function returns a boolean success status.  The
   engine->flow_control_table_lock must be held when this is called. */
Boolean ssh_engine_get_internal_nat_ip(SshEngine engine, SshIpAddr ip_return);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */


/* ssh_engine_nat_register_port() is used to register an <ip:port>
   pair for use. SshEngineNatPort is defined in engine_pm_api.h.
   Engine->flow_control_table_lock must be held when this is called.
   Return FALSE if no SshEngineNatPort structures are available and
   TRUE otherwise. */
Boolean
ssh_engine_nat_register_port(SshEngine engine,
                             const SshIpAddr ip, SshUInt16 port);

/* ssh_engine_nat_register_ports() is used to register
   an <ip_low-ip_high:port> pairs for use. SshEngineNatPort is
   defined in engine_pm_api.h. Engine->flow_control_table_lock
   must be held when this is called.
   Return FALSE if no SshEngineNatPort structures are available and
   TRUE otherwise. */
Boolean
ssh_engine_nat_register_ports(SshEngine engine,
                              const SshIpAddr ip_low,
                              const SshIpAddr ip_high,
                              SshUInt16 port);

/* ssh_engine_nat_unregister_port() signals that a <ip:port>
   pair is not in use. Engine->flow_control_table_lock must be held when
   this is called. */
void
ssh_engine_nat_unregister_port(SshEngine engine,
                               const SshIpAddr ip, SshUInt16 port);

/* ssh_engine_nat_unregister_ports() signals that a
   <ip_low-ip_high:port>
   pair is no longer in use.
   Engine->flow_control_table_lock must be held when
   this is called. */
void
ssh_engine_nat_unregister_ports(SshEngine engine,
                                const SshIpAddr ip_low,
                                const SshIpAddr ip_high,
                                SshUInt16 port);
#endif /* SSHDIST_IPSEC_NAT */

/**********************************************************************
 * Allocation and de-allocation of the engine datastructure.
 **********************************************************************/

SshEngine ssh_engine_alloc(void);

void ssh_engine_free(SshEngine engine);

/* Delayed ssh_engine_stop() in effect. This must be called when the
   engine is stopped and it has no threads active.  This is the final
   free operation for the engine strucuture.  All fields of the engine
   structure must have been freed before this function is called. */
void ssh_engine_stop_now(SshEngine engine);

Boolean
ssh_engine_init_common(SshEngine engine);

/**********************************************************************
 * Triggering-related functions.  The code is in engine_trigger.c.
 **********************************************************************/

/* Sends a trigger message to the policy manager.  This function tries
   not to send more than about one trigger per second for packets with
   same srcip/dstip/proto/srcport/dstip combination.  The reason for
   this is to avoid queuing huge numbers of packets belonging to the
   same stream when there is no rule to process them other than by
   triggering.  An example of such a situation is a sudden "ping -f".
   This provides some denial of service protection.  This returns TRUE
   if the trigger was either sent of ignored (pc->pp is still valid),
   and FALSE if an error occurred that caused pc->pp to become
   invalid. The flow index passed to ssh_engine_trigger must be a
   wrapped index. */
Boolean ssh_engine_trigger(SshEnginePacketContext pc,
                           SshEnginePolicyRule rule,
                           SshUInt32 flow_index);

/**********************************************************************
 * Stuff related to expiring flows and other data structures.  The code
 * is in engine_timeout.c.
 **********************************************************************/


/* This function gets called regularly from a timeout.  This traverses
   through some or all of the flow descriptors in the engine, and
   frees those that have expired.  This is called every
   engine->age_callback_usec microseconds, and should traverse through
   engine->age_callback_flows.  This keeps track of the first flow to
   traverse on the next callback in the engine->age_callback_next
   field.

   See function ssh_engine_age_timeout_schedule. */
void ssh_engine_age_timeout(void *context);

/* Schedule a transform event triggered engine age timeout. */
void ssh_engine_age_timeout_schedule_trd(SshEngine engine, SshTime when);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/**********************************************************************
 * Stuff related to NAT traversal.  The code is in
 * engine_natt_keepalive.c.
 **********************************************************************/

/* This function gets called regularly from a timeout.  This traverses
   through the engine's list of transforms requiring NAT-T keepalive
   messages and sends the keepalive packets. */
void ssh_engine_natt_keepalive_timeout(void *context);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */


/**********************************************************************
 * Debugging stuff.
 **********************************************************************/

#ifdef DEBUG_LIGHT

/* A macro to dump a packet.  This should not fail since
   ssh_interceptor_packet_next_iteration_read() should not fail. */
#define SSH_DUMP_PACKET(level, str, pp)                                      \
do                                                                           \
  {                                                                          \
    size_t _packet_len_, _len_;                                              \
    const unsigned char *_seg_;                                              \
                                                                             \
    _packet_len_ = ssh_interceptor_packet_len(pp);                           \
    SSH_DEBUG((level), ("%s (len=%ld, protocol=%d, flags=0x%lx)",            \
              (str), (long)_packet_len_, pp->protocol,pp->flags));           \
    ssh_interceptor_packet_reset_iteration(pp, 0, _packet_len_);             \
    while (ssh_interceptor_packet_next_iteration_read(pp, &_seg_, &_len_))   \
      {                                                                      \
      SSH_DEBUG_HEXDUMP((level), ("seg len %lx:", (long)_len_), _seg_,       \
                        _len_);                                              \
        ssh_interceptor_packet_done_iteration_read(pp, &_seg_, &_len_);      \
      }                                                                      \
    if (_seg_ != NULL)                                                       \
      ssh_fatal("SSH_DUMP_PACKET freed the packet");                         \
  }                                                                          \
while (0)

#else /* DEBUG_LIGHT */

#define SSH_DUMP_PACKET(level, str, pp)

#endif /* DEBUG_LIGHT */

/* A `sshsnprintf'-compatible renderer function for
   `SshEnginePolicyRule's. */
int ssh_engine_policy_rule_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum);

#endif /* ENGINE_INTERNAL_H */
