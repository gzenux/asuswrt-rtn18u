/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Data types used in the engine_fastpath.h API.
*/

#ifndef ENGINE_FASTPATH_TYPES_H
#define ENGINE_FASTPATH_TYPES_H 1

#include "ipsec_params.h"

#include "sshincludes.h"
#include "sshinet.h"
#include "interceptor.h"
#include "engine.h"
#include "quicksec_pm_shared.h"

/** Flow data structure forward references.  */
typedef struct SshEngineFlowDataRec *SshEngineFlowData;

#include "engine_tcp.h"
#include "engine_udp.h"
#include "engine_icmp.h"

/*--------------------------------------------------------------------*/
/* Types and definitions                                              */
/*--------------------------------------------------------------------*/


/** Number of bytes in the flow ID. */
#define SSH_ENGINE_FLOW_ID_SIZE                 16

/** Data type for an interface number.  This type must be changed if
    more than 256 network interfaces are to be supported. */
typedef SshInterceptorIfnum SshEngineIfnum;

/** Maximum combined key material length for the six-tuple in a bundle
   (in bytes).  This includes both directions. */
#define SSH_IPSEC_MAX_KEYMAT_LEN \
  ((2 * (SSH_IPSEC_MAX_ESP_KEY_BITS + SSH_IPSEC_MAX_MAC_KEY_BITS)) / 8)

/** The maximum size of any supported media header. */
#define SSH_MAX_MEDIAHDR_SIZE   14

/** Number of transform indexes allowed for decapsulation. */
#define SSH_ENGINE_NUM_RX_TRANSFORMS 1

/*--------------------------------------------------------------------*/
/* Status (or action) code for continuing processing in the FastPath.
   This code is typically passed to fastpath_packet_continue
   (declared is engine_fastpath.h). */
/*--------------------------------------------------------------------*/

/** Return value and/or action code for various asynchronous
    operations used inside fastpath_packet_continue. */
typedef enum {
  /** Drop the current packet. */
  SSH_ENGINE_RET_DROP = 1,

  /** Indicates that the packet context should be deinitialized - this
      is used for example when the packet has been sent out, or when
      it has been put into re-assembly data structures;
      this implies that pc->pp has been freed. */
  SSH_ENGINE_RET_DEINITIALIZE,

  /** Restart processing of the packet - this is used for example when
      a packet has been decapsulated from a tunnel; the tunnel_id must
      have been set to the appropriate value before returning this. */
  SSH_ENGINE_RET_RESTART,

  /** Restart processing of the packet, but skip sanity checks /
      pullups and address resolution processing. */
  SSH_ENGINE_RET_IS_SANE,

  /** Restart flow lookup for the packet - this is used for example
      when the policy decision code has created a new flow for the
      packet, and the packet should now be processed according to that
      flow; this is also used when fragmagic decides to process the
      packet as a fragment. */
  SSH_ENGINE_RET_RESTART_FLOW_LOOKUP,

  /** Execute the transform - this assumes that pc->u.flow has been
      initialized with sufficient information about the relevant
      transform, next hop node, and any other processing instructions
      which may be needed. */
  SSH_ENGINE_RET_EXECUTE,

  /** Send the packet - this assumes that pc->pp is ready to be sent
      out to network or to OS protocol stack; pc->media_hdr_len
      is set to the length of media header. */
  SSH_ENGINE_RET_SEND,

  /** An error occurred which has already caused the packet to be
      freed and pc->pp to be invalid (pc is still valid.) */
  SSH_ENGINE_RET_ERROR,

  /** This returns value indicates that the operation was executed
      asynchronously, and a specified function will be called when the
      operation is complete (typically it is possible that the
      function has already been called when this value is returned, or
      it may be called at some later time). */
  SSH_ENGINE_RET_ASYNC,

  /** Another unspecified error occurred - this cannot be used as an
      action code, and is used as an error indicator when pp is still
      valid. */
  SSH_ENGINE_RET_FAIL,

  /** Operation was successfully completed - this is not an action
      code, but is used to indicate a successful return by some
      functions. */
  SSH_ENGINE_RET_OK
} SshEngineActionRet;


/*--------------------------------------------------------------------*/
/* Packet context structure                                           */
/*--------------------------------------------------------------------*/

/** Data type for the packet context object. The object should be accessed
    and modified using the engine_fastpath_util.h API. */
typedef struct SshEnginePacketContextRec *SshEnginePacketContext;

/** Values for public flags in packet context. Other flag values are private
    to the software Fastpath and Engine and must not be modified by the
    FastPath implementation. */

/** If set, then the packet matches the flow in forward direction. */
#define SSH_ENGINE_PC_FORWARD            0x1000

/** If set, then the packet is an IPsec packet directed to local IPsec
    implementation. */
#define SSH_ENGINE_PC_IS_IPSEC           0x2000


/*--------------------------------------------------------------------*/
/* Flow structure                                                     */
/*--------------------------------------------------------------------*/

/** Flow types for protocol-specific processing. */
typedef enum {
  SSH_ENGINE_FLOW_TYPE_RAW,     /** Raw. */
  SSH_ENGINE_FLOW_TYPE_UDP,     /** UDP. */
  SSH_ENGINE_FLOW_TYPE_TCP,     /** TCP. */
  SSH_ENGINE_FLOW_TYPE_ICMP     /** ICMP. */
} SshEngineFlowType;


/* Definition of flags in SshEngineFlowDataRec.data_flags */
#define SSH_ENGINE_FLOW_D_IGNORE_IFNUM   0x00000001 /** Ignore ifnum in
                                                        flowid. */
#define SSH_ENGINE_FLOW_D_IPSECINCOMING  0x00000002 /** IPsec incoming flow. */
#define SSH_ENGINE_FLOW_D_LOCAL_ENDPNT   0x00000004 /** Has local end point. */
#define SSH_ENGINE_FLOW_D_FP_RESERVED    0x00000008 /** Reserved for
                                                        FastPath. */
#define SSH_ENGINE_FLOW_D_FWD_REASSEMBLE 0x00000010 /** Reassemble packets
                                                        fwd. */
#define SSH_ENGINE_FLOW_D_REV_REASSEMBLE 0x00000020 /** Reassemble packets
                                                        rev. */
#ifdef SSHDIST_IPSEC_NAT
#define SSH_ENGINE_FLOW_D_NAT_SRC        0x00000040 /** NAT src fwd, dst in
                                                        rev. */
#define SSH_ENGINE_FLOW_D_NAT_DST        0x00000080 /** NAT dst fwd, src in
                                                        rev. */
#endif /* SSHDIST_IPSEC_NAT */
#ifdef SSHDIST_L2TP
#define SSH_ENGINE_FLOW_D_IGNORE_L2TP    0x00000100 /** Ignore L2TP encaps. */
#endif /* SSHDIST_L2TP */
#define SSH_ENGINE_FLOW_D_FRAG_TRANSFORM 0x00000200 /** Frag before
                                                        transform. */
#define SSH_ENGINE_FLOW_D_VALID          0x00000400 /** Is flow valid? */

#define SSH_ENGINE_FLOW_D_COPY_MASK      0x000007ff /** Mask of flags to
                                                        copy. */

#define SSH_ENGINE_FLOW_D_ERROR_RECEIVED 0x00000800 /** Reverse ICMP error. */
#define SSH_ENGINE_FLOW_D_DROP_PKTS      0x00001000 /** Drop packets
                                                        silently. */
#define SSH_ENGINE_FLOW_D_REJECT_INBOUND 0x00002000 /** Reject inbound
                                                        packets. */
#define SSH_ENGINE_FLOW_D_DANGLING       0x00004000 /** Flow transformations
                                                        currently undefined. */

#define SSH_ENGINE_FLOW_D_NO_LRU_REAP    0x00008000 /** Do not reap this
                                                       flow. */

#define SSH_ENGINE_FLOW_D_SPECIAL_FLOW   0x00010000 /** Pass special flow
                                                        packets always to
                                                        engine slowpath. */

/* Mask 0x0fff reserved for flags copied to SshEnginePacketContext.flags. */

/** The SshEngineFlowDataRec is the fastpath portion of SshEngineFlowRec.
    Access and manipulation of these fields must be done via
    FASTPATH_{GET,COMMIT}_FLOW(). */
typedef struct SshEngineFlowDataRec
{
  /** Flow ID for the forward direction - for IPsec flows, this is normally
      set to all zeroes (meaning an invalid forward flow id).  However, for
      a short period after rekey (while the old SPIs can still be
      used) this will be the old flow ID; in that case the
      SSH_ENGINE_FLOW_REKEYOLD flag will be set, and the
      SSH_ENGINE_PC_FORWARD flag will not be set for 'pc' but
      SSH_ENGINE_FLOW_REKEYOLD will be set instead - note that we rely
      on the hash of the data going into flow id being sufficient as
      the definitive flow id; this is based on the probability of
      false matches with good 128 bit hashes being extremely low (on
      the order of 10^-100 for each new flow, which is much less than
      the probability of random CPU malfunctions). */
  unsigned char forward_flow_id[SSH_ENGINE_FLOW_ID_SIZE];

  /** Flow id for the reverse direction - for IPsec flows this is the current
      flow id for incoming IPsec traffic (note that the flow id
      might not be for an AH/ESP packet; it could also be UDP when NAT
      Traversal is used.) */
   unsigned char reverse_flow_id[SSH_ENGINE_FLOW_ID_SIZE];

  /** Original source IP address of the packet that caused the flow to
      be created - this information can be used for example in user interfaces
      to understand what the flow relates to; this is also used internally
      by the system (for example in the NAT implementation). */
  SshIpAddrStruct src_ip;

  /** Original destination IP address of the packet that caused the flow to
      be created - this information can be used for example in user interfaces
      to understand what the flow relates to; this is also used internally
      by the system (for example in the NAT implementation). */
  SshIpAddrStruct dst_ip;

  /** Original source port number of the packet that caused the flow to
      be created - this information can be used for example in user interfaces
      to understand what the flow relates to; this is also used internally
      by the system (for example in the NAT implementation); the port
      number is valid only for TCP and UDP; if pc->ipproto == ICMP,
      then the ICMP type/code is encoded in dst_port as "(type << 8)|code"
      and the ICMP identifier in src_port. */
  SshUInt16 src_port;

  /** Original destination port number of the packet that caused the flow to
      be created - this information can be used for example in user interfaces
      to understand what the flow relates to; this is also used internally
      by the system (for example in the NAT implementation); the port
      number is valid only for TCP and UDP; if pc->ipproto == ICMP,
      then the ICMP type/code is encoded in dst_port as "(type << 8)|code"
      and the ICMP identifier in src_port. */
  SshUInt16 dst_port;

  /** Flags for the flow descriptor. */
  SshUInt32 data_flags;

  /** If a PMTU message has been received for this flow, these
      MTU values are used. */
  SshUInt32 forward_pmtu;
  SshUInt32 reverse_pmtu;

#ifdef SSHDIST_IPSEC_NAT
  /** NAT'd source address. */
  SshIpAddrStruct nat_src_ip;
  /** NAT'd destination address. */
  SshIpAddrStruct nat_dst_ip;
  /** NAT source port. */
  SshUInt16 nat_src_port;
  /** NAT destination port. */
  SshUInt16 nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /** Outgoing interface number for this flow in the forward direction. */
  SshEngineIfnum forward_ifnum;
  /** Outgoing interface number for this flow in the reverse direction. */
  SshEngineIfnum reverse_ifnum;
  /** The local value for this flow in the forward direction. */
  SshUInt8 forward_local;
  /** The local value for this flow in the reverse direction. */
  SshUInt8 reverse_local;
  /** The MTU value for this flow in the forward direction. */
  SshUInt16 forward_mtu;
  /** The MTU value for this flow in the reverse direction. */
  SshUInt16 reverse_mtu;
  /** The route selector value for this flow in the forward direction. */
  SshUInt32 forward_route_selector;
  /** The route selector value for this flow in the reverse direction. */
  SshUInt32 reverse_route_selector;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  /** Index of the next hop nodes for this flow in the forward direction
      - if this is not used, then it is SSH_IPSEC_INVALID_INDEX. */
  SshUInt32 forward_nh_index;
  /** Index of the next hop nodes for this flow in the reverse direction
      - if this is not used, then it is SSH_IPSEC_INVALID_INDEX. */
  SshUInt32 reverse_nh_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /** Index of the transform to apply to packets that are processed using
      this flow in the forward direction - this is SSH_IPSEC_INVALID_INDEX
      if no transform is to be applied; otherwise this will be the transform
      index for the trd. */
  SshUInt32 forward_transform_index;

  /** Index of the transform to apply to packets that are processed using
      this flow in the reverse direction - this is SSH_IPSEC_INVALID_INDEX
      if no transform is to be applied; otherwise this will be the transform
      index for the trd. */
  SshUInt32 reverse_transform_index;

  /** Index of the transform that is allowed for inbound transform of packets
      of this flow in the forward direction - a packet may be decapsulated
      using the outbound transform index (above) or with this transform_index;
      This transform index may get updated if the packets of this flow
      are received through multiple SAs; updating this does not change
      the transform used for outbound transform.*/
  SshUInt32 forward_rx_transform_index[SSH_ENGINE_NUM_RX_TRANSFORMS];

  /** Index of the transform that is allowed for inbound transform of packets
      of this flow in the reverse direction - a packet may be decapsulated
      using the outbound transform index (above) or with this transform_index;
      This transform index may get updated if the packets of this flow
      are received through multiple SAs; updating this does not change
      the transform used for outbound transform.*/
  SshUInt32 reverse_rx_transform_index[SSH_ENGINE_NUM_RX_TRANSFORMS];

  /** Time when the last packet was sent using this flow - this value is
      protected using engine->flow_control_table_lock. */
  SshTime last_packet_time;

  /** Flow generation for detecting raceconditions. */
  SshUInt8 generation;

  /** Protocol-specific state. */
  SshUInt8 type; /* SshEngineFlowType */

  /** IP proto - moved here for better packing. */
  SshUInt8 ipproto;

  /** Interface number for checking that the packet arrived on the correct
      interface in case of a flow_id collision, forward direction.

      @internal
      With the current implementation, this could be computed from
      forward_ifnum or forward_nh_index, but ssh_engine_create_flow()
      does not enforce this and this struct had at least 16 bytes of padding
      currently available, so it is better to keep these here separate. */
  SshEngineIfnum incoming_forward_ifnum;

  /** Interface number for checking that the packet arrived on the correct
      interface in case of a flow_id collision, reverse direction.

      @internal
      With the current implementation, this could be computed from
      reverse_ifnum or reverse_nh_index, but ssh_engine_create_flow()
      does not enforce this and this struct had at least 16 bytes of padding
      currently available, so it is better to keep these here separate. */
  SshEngineIfnum incoming_reverse_ifnum;

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  union {
    SshEngineTcpDataStruct tcp;
    SshEngineUdpDataStruct udp;
    SshEngineIcmpDataStruct icmp;
  } u;
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

  /** SPI for NAT-T flows and DHCP XID for DHCP flows. */
  SshUInt32 protocol_xid;

#ifdef SSH_IPSEC_STATISTICS
  /** Statistics information for the flow. */
  SshEngineFlowStatsStruct stats;
#endif /* SSH_IPSEC_STATISTICS */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /** Flow LRU level */
  SshUInt32 flow_lru_level;

  /** VRI ID */
  SshVriId routing_instance_id;
} SshEngineFlowDataStruct;



/*--------------------------------------------------------------------*/
/* Next hop data type                                                 */
/*--------------------------------------------------------------------*/

/* Flags for next hop nodes. */
#define SSH_ENGINE_NH_VALID             0x0001 /** Node is valid and ready. */
#define SSH_ENGINE_NH_EMBRYONIC         0x0002 /** Node being constructed. */
#define SSH_ENGINE_NH_LOCAL             0x0004 /** Send to local stack. */
#define SSH_ENGINE_NH_INBOUND           0x0008 /** For an inbound packet. */
#define SSH_ENGINE_NH_OUTBOUND          0x0010 /** For an outbound packet. */
#define SSH_ENGINE_NH_REROUTE           0x0020 /** Reroute node when possible.
                                                */
#define SSH_ENGINE_NH_TRANSFORM_APPLIED 0x0040 /** For transform. */
#define SSH_ENGINE_NH_FORWARD           0x0080 /** For forwarded packets. */
#define SSH_ENGINE_NH_FAILED            0x0100 /** Node construction failed. */

/** The SshEngineNextHopDataRec is the FastPath portion of SshEngineNextHopRec.
    Access and manipulation of these fields must be done via
    FASTPATH_{GET,COMMIT}_NH(). */
typedef struct SshEngineNextHopDataRec
{
  /** Address of the peer, can be undefined - generally valid
      only for inbound packets. */
  SshIpAddrStruct src;

  /** The address of the next hop gateway. */
  SshIpAddrStruct dst;

  /** Interface number to which the packet should be sent - this is also used
      to contain the index of this next hop node when the node is on
      freelist. */
  SshEngineIfnum ifnum;

  /** Media type for the outgoing interface. */
  SshUInt8 mediatype;

  /** Length of the media header in bytes. */
  SshUInt8 media_hdr_len;

  /** Minimum packet length in bytes (if shorter, the packet must be padded
      at the end). */
  SshUInt8 min_packet_len;

  /** Protocol for the packet after adding media header (SSH_PROTOCOL_OTHER
      if the protocol should not be changed). */
  SshUInt8 media_protocol;

  /** Flags for this next hop node. */
  SshUInt16 flags;

  /** Media header to be prepended to packets. */
  unsigned char mediahdr[SSH_MAX_MEDIAHDR_SIZE];

  /** Path MTU for the destination, or link MTU if not known - this is
      the information obtained from the system; the Path MTU discovery
      performed for IPsec flows modifies the value in the transform
      object, not this one. */
  size_t mtu;

} SshEngineNextHopDataStruct, *SshEngineNextHopData;

/*--------------------------------------------------------------------*/
/* Transform structure                                                */
/*--------------------------------------------------------------------*/


/** The SshEngineTransformDataRec is the FastPath portion of
    SshEngineTransformRec. Access and manipulation of these fields must
    be done via FASTPATH_{GET,COMMIT}_TRD(). */
typedef struct SshEngineTransformDataRec
{
  /** Transform description - this is the same as the parameters for "tunnels"
      in the policy manager API (SSH_PM_CRYPT_*, SSH_PM_MAC_*,
      SSH_PM_COMPRESS_*, SSH_PM_IPSEC_* bits), except that only one CRYPT
      algorithm can be chosen, only one MAC algorithm can be chosen, and
      SSH_PM_IPSEC_TUNNEL, SSH_PM_IPSEC_NATT, and SSH_PM_IPSEC_L2TP flags must
      be specified explicitly if the corresponding encapsulations are
      desired. */
  SshPmTransform transform;

  /** Remote gateway address for IPSEC tunnel mode ("tunnel-to") - this must
      always be set to the peer's address (also in transport mode); this is
      used in IKE initial contact notification processing as the key to find
      the transforms/SAs that should be deleted; for NAT-T and L2TP, this is
      the remote destination to put in UDP packets. */
  SshIpAddrStruct gw_addr;

  /** Own IP address for this transform - this is used as our address when
      creating IP-in-IP headers (for tunnel mode), NAT-T headers, or L2TP
      headers; this field must be initialized by the Policy Manager. */
  SshIpAddrStruct own_addr;

  /** Interface number on which 'own_addr' resides - this field must be
      initialized by the Policy Manager. */
  SshEngineIfnum own_ifnum;

#ifdef SSHDIST_L2TP
/* Bit masks for L2TP_flags. */
#define SSH_ENGINE_L2TP_SEQ             0x01 /** Add Ns and Nr in L2TP hdr. */
#define SSH_ENGINE_L2TP_PPP_ACFC        0x10 /** Add ACFC in PPP hdr. */
#define SSH_ENGINE_L2TP_PPP_PFC         0x20 /** Add PFC in PPP hdr. */

  /** Local port number for L2TP UDP encapsulation. */
  SshUInt16 l2tp_local_port;
  /** Remote port number for L2TP UDP encapsulation. */
  SshUInt16 l2tp_remote_port;
  /** Local tunnel ID. */
  SshUInt16 l2tp_local_tunnel_id;
  /** Local session ID. */
  SshUInt16 l2tp_local_session_id;
  /** Remote tunnel ID. */
  SshUInt16 l2tp_remote_tunnel_id;
  /** Remote session ID. */
  SshUInt16 l2tp_remote_session_id;
  /** L2TP Ns sequence number. */
  SshUInt16 l2tp_seq_ns;
  /** L2TP Nr sequence number. */
  SshUInt16 l2tp_seq_nr;
  /** L2TP flags. */
  SshUInt8 l2tp_flags;
#endif /* SSHDIST_L2TP */

  /** Identify the local IKE server used. */
  SshUInt16 local_port;

  /** Remote port number for NAT-T (NAT Traversal) - this must always be set
      to the remote port if NAT-T is supported (even if NAT-T is not enabled
      for the given tunnel). */
  SshUInt16 remote_port;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
#define SSH_ENGINE_NATT_OA_L              0x01 /** NAT-OA local specified. */
#define SSH_ENGINE_NATT_OA_R              0x02 /** NAT-OA remote specified. */
#define SSH_ENGINE_NATT_LOCAL_BEHIND_NAT  0x10 /** Local end behind NAT. */
#define SSH_ENGINE_NATT_REMOTE_BEHIND_NAT 0x20 /** Remote end behind NAT. */
  /** Flags controlling NAT-T UDP encapsulation and its options. */
  SshUInt8 natt_flags;

  /** NAT Original Address for the local end - this is valid if the
      SSH_ENGINE_NATT_OA_L flag is set in 'natt_flags'; the type
      (IPv4/IPv6) of the NAT-OA is the same as the type of the 'gw_addr'. */
  unsigned char natt_oa_l[SSH_IP_ADDR_SIZE];

  /** NAT Original Address for the remote end - this is valid if the
      SSH_ENGINE_NATT_OA_R flag is set in 'natt_flags'; the type
      (IPv4/IPv6) of the NAT-OA is the same as the type of the 'gw_addr'. */
  unsigned char natt_oa_r[SSH_IP_ADDR_SIZE];

#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /** The tunnel id which we will use when we restart processing of the packet
      after decapsulating from inbound tunnel - however, certain special
      packets, namely NAT-T packets without proper NAT-T marker (i.e., IKE
      packets) and L2TP control packets are sent to tunnel_id 1 instead of
      this one. */
  SshUInt32 inbound_tunnel_id;

  /** SPIs for the transform - the SSH_PME_SPI_* values are indexes to
     this array; unused SPIs must be set to zero. */
  SshUInt32 spis[6];

  /** Key material - taken from this buffer as follows:

      starting at index 0:
         - esp enc in (if present) (SSH_IPSEC_MAX_ESP_KEY_BITS/8)
         - ah/esp mac in (if present) (SSH_IPSEC_MAX_MAC_KEY_BITS/8)

      starting at index SSH_IPSEC_MAX_KEYMAT_LEN/2:
         - esp enc out (if present) (SSH_IPSEC_MAX_ESP_KEY_BITS/8)
         - ah/esp mac out (if present) (SSH_IPSEC_MAX_MAC_KEY_BITS/8)

      If using counter mode encryption, the cipher nonce directly follows the
      ESP encryption key material; note that this implies that the cipher key
      length plus the cipher nonce length must be no larger than
      SSH_IPSEC_MAX_ESP_KEY_BITS; the cipher nonce length is 32 bits; for CBC
      mode of encryption the cipher nonce is not present.  */
  unsigned char keymat[SSH_IPSEC_MAX_KEYMAT_LEN];

  /** The maximum number of bytes by which the packet expands after outbound
      transforms - the actual packet expansion value for a given packet
      may be less than this value depending on the amount of padding that is
      added for the transform, or if IP payload compression is applied. */
  SshUInt8 packet_enlargement;

  /** Cipher key size (in bytes). */
  SshUInt8 cipher_key_size;

  /** Cipher iv size (that which is sent on the wire) in bytes. */
  SshUInt8 cipher_iv_size;

  /** Cipher nonce size (only non-zero for counter mode) in bytes. */
  SshUInt8 cipher_nonce_size;

  /** MAC key size (in bytes). */
  SshUInt8 mac_key_size;

  /** When the transform data is passed back to the Policy Manager (e.g., for
      trigger), this will be "run_time" value when the transform has last been
      used.  "Run time" means the approximate time (in seconds) since the
      engine was started.  This can be used by the policy manager to decide
      whether to rekey the transform or let it expire.  This is initialized to
      zero by the engine when the transform is installed.  This is not
      affected by rekey. */
  SshTime last_in_packet_time;
  SshTime last_out_packet_time;

#ifdef SSH_IPSEC_STATISTICS
  /** Statistics counters for the transform. */
  SshEngineTransformDataStatsStruct stats;
#endif /** SSH_IPSEC_STATISTICS */

  /** Old SPI values from before rekey. */
  SshUInt32 old_spis[6];

  /** Old replay mask for replay prevention for use in the period
      after rekey when the old incoming SAs are still valid. */
  SshUInt32 old_replay_mask[SSH_ENGINE_REPLAY_WINDOW_WORDS];

  /** Old replay offset high value for replay prevention for use in the
      period after rekey when the old incoming SAs are still valid. */
  SshUInt32 old_replay_offset_high;

  /** Old replay offset low value for replay prevention for use in the
      period after rekey when the old incoming SAs are still valid. */
  SshUInt32 old_replay_offset_low;

  /** Old incoming key material from before rekey. */
  unsigned char old_keymat[SSH_IPSEC_MAX_KEYMAT_LEN / 2];

  /** The 64-bit packet counter for outgoing packets, made of two 32-bit
      unsigned integers - if no outbound packets have been processed by this
      transform both of these values are zero; the SSH_UINT64_INC() macro
      should be used for incrementing the 64-bit value, SSH_UINT64_IS_ZERO()
      macro to test for zero, and SSH_UINT64_OVERFLOW() macro to test for
      overflow. */
#define SSH_UINT64_INC(low, high) \
  do { if ((low) == 0xffffffff) { (high)++; (low) = 0;} else (low)++; } \
  while (0)
#define SSH_UINT64_IS_ZERO(low, high) ((low) == 0 && (high) == 0)
#define SSH_UINT64_OVERFLOW(low, high) ((low) == 0xffffffff && \
                                       (high) == 0xffffffff)
  SshUInt32 out_packets_high;
  SshUInt32 out_packets_low;

  /** Replay prevention bit mask for incoming packets. */
  SshUInt32 replay_mask[SSH_ENGINE_REPLAY_WINDOW_WORDS];

  /** Packet counter value corresponding to bit 0 of replay_mask (for incoming
      packets only) - Policy Manager can compare this and replay_mask,
      both against 0, to see if any inbound packets have been processed by
      this transform. */
  SshUInt32 replay_offset_high;

  /** Packet counter value corresponding to bit 0 of replay_mask (for incoming
      packets only) - Policy Manager can compare this and replay_mask,
      both against 0, to see if any inbound packets have been processed by
      this transform. */
  SshUInt32 replay_offset_low;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /** A buffer for an extension selector - if 'decapsulate_extension' is set
      (see below) then this value will override any pp->extension value when
      decapsulating packets with this transform. */
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

#ifdef SSH_IPSEC_TCPENCAP
  /** Encapsulating TCP connection identifier - this is set to
      SSH_IPSEC_INVALID_INDEX if the transform does not specify
      IPsec over TCP encapsulation. */
  SshUInt32 tcp_encaps_conn_id;
#endif /* SSH_IPSEC_TCPENCAP */

  /** Path MTU value received from the route, following this
      transform - this has the value 0 if the path MTU is not
      received. */
  SshUInt16 pmtu_received;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /** If this flag is set, then the extension selector in 'extension'
      will overwrite the pp->extension value for decapsulated packets. */
  SshUInt8 decapsulate_extension : 1;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

#define SSH_ENGINE_DF_KEEP   0  /** Keep DF bit. */
#define SSH_ENGINE_DF_SET    1  /** Set DF bit. */
#define SSH_ENGINE_DF_CLEAR  2  /** Clear DF bit. */
  /** IPv4 DF bit processing when IPsec is performed. */
  SshUInt8 df_bit_processing : 2;

  /** Restart packet processing after transform execution for another
      round of nested tunneling. */
  SshUInt8 restart_after_tre : 1;

  /** Nesting level for this transform - this is used currently for
      debugging and asserts. */
  SshUInt8 nesting_level;

  /** Wrapped transform index (transform index and generation) - this is
      currently used internally by the software FastPath implementation
      for matching TRD's to transform contexts. */
  SshUInt32 tr_index;

} SshEngineTransformDataStruct, *SshEngineTransformData;

#endif /* ENGINE_FASTPATH_TYPES_H */
