/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Declarations and definitions private to the software FastPath
   implementation.
*/

#ifndef FASTPATH_SWI_H
#define FASTPATH_SWI_H 1

#include "fastpath_accel.h"

#ifdef SSHDIST_IPSEC_IPCOMP
#include "engine_ipcomp_glue.h"
#endif /* SSHDIST_IPSEC_IPCOMP */

/** Allocation of the FastPath object.

    @return
    Returns NULL on failure. */
SshFastpath ssh_fastpath_alloc(SshEngine engine);

/** Free the FastPath object. */
void ssh_fastpath_free(SshFastpath fastpath);

/** Initialize the crypto library */
void fastpath_crypto_init(void);


/* ********************************************************************
 * Data structures and functions for fragmentation and reassembly.
 * ********************************************************************/

/** Fragmentation context.  This is used to contain state while a packet
    is being fragmented. */
typedef struct SshFastpathFragmentContextRec
{
  SshInterceptorPacket pp;
  size_t mtu;
  size_t offset;
  size_t total_len;
  SshUInt16 frag_hlen;
  SshUInt16 frag_data_len;
  union
  {
    struct
    {
      size_t hdrlen;
      SshUInt16 frag_optlen;
      SshUInt16 frag1_optlen;
      SshUInt16 frag1_hlen;
      SshUInt16 frag1_data_len;
      Boolean df_on_first_fragment;
      unsigned char frag_hdr[SSH_IPH4_HDRLEN];
      unsigned char frag_options[SSH_IPH4_MAX_HEADER_LEN - SSH_IPH4_HDRLEN];
      unsigned char frag1_options[SSH_IPH4_MAX_HEADER_LEN - SSH_IPH4_HDRLEN];
    } ipv4;
#if defined (WITH_IPV6)
    struct
    {
      /* In the IPv6 fragmentation we can't use any of the fixed size
         arrays above, but we need to retain the original packet's
         unfragmentable part in full, and we use the `fragh_offset'
         and `fragh_offset_prevnh' fields copied from the original
         packet's packet context. */
      SshUInt16 fragh_offset;
      SshUInt16 fragh_offset_prevnh;
      SshUInt32 id;
    } ipv6;
#endif /* WITH_IPV6 */
  } u;
  /* The following fields are used only by IPv4 */
} SshFastpathFragmentContextStruct, *SshFastpathFragmentContext;


/** Initialize the fragmentation context for fragmenting the given
    packet.

    @return
    This returns TRUE if the packet has the DF bit set (in
    which case 'pc->pp' is not freed, and ssh_fastpath_fragc_uninit
    should not be called), and otherwise returns FALSE (in which case
    'pc->pp' is freed either by this function or by a later call to
    ssh_fastpath_fragc_uninit). */
Boolean ssh_fastpath_fragc_init(SshFastpath fastpath,
                                SshFastpathFragmentContext fragc,
                                SshEnginePacketContext pc,
                                size_t mtu,
                                Boolean df_on_first_fragment);

/** Returns the next fragment for the packet, or NULL if there are
    no more fragments.  This also returns NULL if an error occurs. */
SshInterceptorPacket ssh_fastpath_fragc_next(SshFastpath fastpath,
                                             SshFastpathFragmentContext fragc);

/** Deinitializes the fragmentation context.  This basically just frees
    the original packet. */
void ssh_fastpath_fragc_uninit(SshFastpath fastpath,
                               SshFastpathFragmentContext fragc);



/* **************** Reassembly and fragment magic ***********************/

/* Flags for fragment entries.  The HAVE_LAST and HAVE_FIRST flags are also
   used in pd->frag_flags in reassembly queues. */
#define SSH_ENGINE_FRAG_REASSEMBLE      0x01 /** Reassemble this packet. */
#define SSH_ENGINE_FRAG_QUEUED_LAST     0x02 /** Enqueued frag without MF
                                                 set. */
#define SSH_ENGINE_FRAG_QUEUED_FIRST    0x04 /** Enqueued first frag. */
#define SSH_ENGINE_FRAG_SENT_LAST       0x08 /** Sent last frag. */
#define SSH_ENGINE_FRAG_SENT_FIRST      0x10 /** Sent first frag. */
#define SSH_ENGINE_FRAG_REJECT          0x20 /** Reject this packet. */

/** Data structure for fragment ID. */
typedef struct SshFastpathFragIdRec
{
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshUInt32 id;
  SshUInt8 ipproto;
} SshFastpathFragIdStruct, *SshFastpathFragId;

/** Data structure kept for each packet being reassembled or each fragment
    magic entry. */
typedef struct SshFastpathFragEntryRec
{
  SshFastpathFragIdStruct frag_id[1];

  /** Pointer to the next fragment entry in the hash chain. */
  struct SshFastpathFragEntryRec *hash_next;

  /** Flow id for packets that are to be processed as fragments. */
  unsigned char flow_id[SSH_ENGINE_FLOW_ID_SIZE];

  /** List of the individual fragments that we have stored.  This list is
      singly linked by pp->next, in the ascending order of fragment
      offset.  pd->frag_offset, pd->frag_len, and pd->frag_flags are used to
      contain information about the fragment. */
  SshInterceptorPacket pp_chain;

  /** Time (engine->run_time) when this entry expires. */
  SshTime expiration;

  /** Links for the doubly linked list of all fragment magic entries. */
  struct SshFastpathFragEntryRec *all_lru_next;
  struct SshFastpathFragEntryRec *all_lru_prev;

  /** Links for the doubly linked list of fragment magic / reassembly entries
      with data. */
  struct SshFastpathFragEntryRec *data_lru_next;
  struct SshFastpathFragEntryRec *data_lru_prev;

  /** Reassembly/fragmagic flags. */
  SshUInt8 flags;

  /** Number of fragments in pp_chain. */
  SshUInt8 num_frags;

  /** Total size of the packet (valid only if we have seen a packet without MF
      set). */
  SshUInt16 packet_size;

  /** Offset of next valid packet in loose monitoring mode. */
  SshUInt16 next_offset;

  /** Minimum size of the packet in loose/strict monitoring mode. */
  SshUInt16 min_packet_size;

  /** Total number of bytes in buffer. */
  SshUInt16 total_bytes;

  /** The tunnel id for this fragment. */
  SshUInt32 tunnel_id;

  /** The interface fragment was received upon. */
  SshEngineIfnum ifnum;
} SshFastpathFragEntryStruct, *SshFastpathFragEntry;

/** Performs fragment magic on a fragment.  This may queue the packet,
    reassemble, or process the packet according to a previously defined
    flow.

    @param reassemble
    If 'reassemble' is TRUE (significant for first frags only), that
    indicates that the packet should be reassembled before processing.
    If 'reassemble' is FALSE, that means that the packet should not be
    reassembled, but that all fragments should be processed as if
    their flow id was pc->flow_id.

    @return
    This returns SSH_ENGINE_RET_OK if processing of the packet is
    now complete (i.e., "deinitialize" should be performed), and
    SSH_ENGINE_RET_CONTINUE if processing of the packet should
    continue as a fragment.  If this successfully completes
    reassembly, this returns SSH_ENGINE_RET_RESTART, in which case
    processing the packet should be restarted (i.e., it should
    again go through sanity checks).  This may also return
    SSH_ENGINE_RET_ERROR if an error causes pc->pp to be freed, and
    SSH_ENGINE_RET_DROP if it should be dropped.

   */
SshEngineActionRet
ssh_fastpath_fragmagic(SshFastpath fastpath, SshEnginePacketContext pc,
                       Boolean reassemble);


/** Add the given fragmagic entry to the LRU list of all fragmagic entries. */
void ssh_fastpath_fragmagic_add_all_lru(SshFastpath fastpath,
                                        SshFastpathFragEntry fe);

/** Add the entry to the fragmagic hash table. */
void ssh_fastpath_fragmagic_add_hash(SshFastpath fastpath,
                                     SshFastpathFragEntry fe);

/** This function is called periodically from a timeout.  This clears all
    expired entries from the end of the data LRU.  The purpose of this is
    to cause the reassembly data structures to become empty with time if
    previously there were a lot of packets with missing fragments (often
    a result of an attack attempt), and such fragments are no longer being
    received.  This basically just causes the packet buffers to be released
    for other uses. */
void ssh_fastpath_fragmagic_timeout(void *context);

/** Drop all fragments currently in fragmentation.

    This may not be called with locks held.

    @return
    Returns the number of fragments that were freed.  If there are no
    more packets in queue with data, then this returns NULL.

    */
SshUInt32 ssh_fastpath_fragmagic_drop_all(SshFastpath fastpath);


/* **************** Transform Contexts ***********************/

/* Use per-CPU freelists for crypto transform contexts unless we are using
   hardware accelerators. When using asychronous hardware accelerators it
   is very often the case that a crypto transform completes on a different
   CPU from which is was started on. This cancels any advantage on SMP systems
   that can be gained from using per-CPU freelists for crypto transforms and
   so is disabled, reverting to a single freelist protected by a kernel
   mutex lock. */
#ifndef SSH_IPSEC_HWACCEL_CONFIGURED
#define SSH_FASTPATH_PER_CPU_TRANSFORM_CONTEXTS
#endif /* !SSH_IPSEC_HWACCEL_CONFIGURED */

/* How many transform contexts can be held per block? */
#define SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshFastpathTransformContextStruct))

#ifdef DEBUG_LIGHT
#define SSH_FASTPATH_GET_TRC(fastpath, idx)                                  \
(((idx) >= SSH_ENGINE_MAX_TRANSFORM_CONTEXTS                                 \
 ? ssh_fatal("transform context index out of bounds  ")                      \
   , (SshFastpathTransformContext)NULL                                       \
 :&((fastpath)->tc_table_root[(idx)/SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE]\
                           [(idx)%SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE])))
#else
#define SSH_FASTPATH_GET_TRC(fastpath, idx)                                  \
(&((fastpath)->tc_table_root[(idx)/SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE] \
                          [(idx)%SSH_ENGINE_TRANSFORM_CONTEXTS_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */

/* Transform context hash table size is currently limited by maximum
   mallocable memory size. */
#ifndef SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE
#define SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE                       \
  (SSH_ENGINE_MAX_TRANSFORM_CONTEXTS >                               \
   (SSH_ENGINE_MAX_MALLOC / sizeof(SshUInt32)) ?                     \
   (SSH_ENGINE_MAX_MALLOC / sizeof(SshUInt32)) :                     \
    SSH_ENGINE_MAX_TRANSFORM_CONTEXTS)
#endif /* SSH_ENGINE_TRANSFORM_CONTEXT_HASH_SIZE */

/* Transform context data structure.  This data structure contains
   encryption context and other optimized state for processing packets
   according to a security association.  Transform contexts are cached
   because the initialization of software implementations of some ciphers
   is relatively expensive. */
typedef struct SshFastpathTransformContextRec
{
  /* Index of this transform context (initialized at startup). */
  SshUInt32 self_index;

  /* The CPU from which this packet context was allocated from. */
  unsigned int cpu;

  /* Index for the transform. */
  SshUInt32 tr_index;

  /* Key material for the transform.  This is only used for finding the
     correct transform. */
  unsigned char keymat[SSH_IPSEC_MAX_KEYMAT_LEN / 2];
  /* SPI values for the transform. */
  SshUInt32 ah_spi;
  SshUInt32 esp_spi;
#ifdef SSHDIST_IPSEC_IPCOMP
  /* Only the lower 16 bit will be used. */
  SshUInt16 ipcomp_cpi;
#endif /* SSHDIST_IPSEC_IPCOMP */
  /* The transform that is being performed. */
  SshUInt64 transform;

  /* Pointers for the LRU list. */
  SshUInt32 lru_prev;
  SshUInt32 lru_next;

  /* Pointer for the hash list. */
  SshUInt32 hash_next;

  void *sw_crypto;

  SshUInt8 with_sw_auth_cipher;
  SshUInt8 with_sw_mac;
  SshUInt8 with_sw_cipher;

#ifdef SSHDIST_IPSEC_IPCOMP
  /* IPComp descriptor. This is NULL if no compression is to performed. */
  const SshCompressDefStruct *compress;

  /* Compression context, or NULL if hardware does the compression or no
   compression is to be performed. */
  void *compression_context;
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Hardware acceleration context for accelerating the full transform
     (i.e., "combined" acceleration), or NULL if none is available. */
  SshHWAccel transform_accel;

  /* Indication of which requested features the accelerator did not
     provide. */
  SshUInt32 accel_unsupported_mask;

  /* Hardware acceleration context for accelerating both encryption
     and message authentication computation, or NULL if none is
     available (or if transform_accel is set). */
  SshHWAccel encmac_accel;

  /* Hardware acceleration context for accelerating encryption only (MAC
     needs to be performed in software), or NULL if not available (or if
     transform_accel or encmac_accel is set). */
  SshHWAccel enc_accel;

  /* Hardware acceleration context for accelerating the MAC only (encryption
     needs to be performed in software), or NULL if not available (or if
     transform_accel or encmac_accel is set). */
  SshHWAccel mac_accel;

  /* Number of packets currently using this transform context.  For normal
     contexts (software or encmac/enc acceleration), the same context can be
     used by only one packet.  However, for transform-accelerated contexts
     the same context can be shared by many packets.  Destroying the context
     is delayed until the reference count reaches zero. */
  SshUInt32 refcnt;

  /* Flag indicating that this transform context has been deleted and
     should be destroyed when its reference count reaches zero. */
  SshUInt8 destroy_pending;

  /* Flag indicating whether this transform context is for IPv4 (0) or
     IPv6 (1). */
  SshUInt8 ipv6;

  /* Flag indicating whether this transform context is for input (0)
     or output (1). */
  SshUInt8 for_output;

  /* This is non-zero if the prefix starts at the beginning of the packet,
     as opposed to after the IP header.  In other words, this is non-zero
     if the packet is tunneled (IP-in-IP or L2TP). */
  SshUInt8 prefix_at_0;

  /* IP header length (for IPv4 or IPv6).  Note that received length may
     differ due to options. */
  SshUInt8 iphdrlen;

  /* Size of a cipher block. */
  SshUInt8 cipher_block_len;

  /* Cipher IV len */
  SshUInt8 cipher_iv_len;

  /* Boolean value, 1 if using counter mode encryption, otherwise 0 */
  SshUInt8 counter_mode;

  /* Size of the digest (ICV) returned by the MAC. */
  SshUInt8 icv_len;

  /* Combined length of supported prefix headers NATT, ESP, UDP+L2TP
     or IPIP. */
  SshUInt8 prefix_len;

  /* Trailer length excluding padding.  This is only used if
     SSH_PM_IPSEC_ESP was specified. */
  SshUInt8 trailer_len;

  /* Next header/IPPROTO value for the IP header. */
  SshUInt8 ip_nh;

  /* Length of the NAT-T header, or 0 if there is no NAT-T header. */
  SshUInt8 natt_len;

#ifdef SSH_IPSEC_AH
  /* Offset of the AH header in the prefix.  This is valid if SSH_PM_IPSEC_AH
     is specified. */
  SshUInt8 ah_ofs;

  /* Next header value for AH. */
  SshUInt8 ah_nh;

  /* Padding length (if necessary to make AH header 32 or 64 bit aligned)
     This would be set mostly for IPv6 cases when icv_len + 12 is not a
     multiple of 8. */
  SshUInt8 ah_hdr_pad_len;
#endif /* SSH_IPSEC_AH */

  /* Offset of ESP header in the prefix.  This is valid if
     SSH_PM_IPSEC_ESP was specified. */
  SshUInt8 esp_ofs;

  /* Length of the ESP header in the prefix, or 0 if there is no ESP header. */
  SshUInt8 esp_len;

  /* Next header value for ESP. */
  SshUInt8 esp_nh;

#ifdef SSHDIST_IPSEC_IPCOMP
  /* Offset of the IPComp header in the prefix.*/
  SshUInt8 ipcomp_ofs;

  /* Next header value for IP Comp header */
  SshUInt8 ipcomp_nh;
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Offset of NATT header in the prefix.  This is valid if
     SSH_PM_IPSEC_NATT was specified. */
  SshUInt8 natt_ofs;

#ifdef SSHDIST_L2TP
  /* Offset of UDP + L2TP header in the prefix.  This is valid if
     SSH_PM_IPSEC_L2TP was specified. */
  SshUInt8 l2tp_ofs;
#endif /* SSHDIST_L2TP */

#ifdef SSH_IPSEC_TCPENCAP
  /* Overhead of IPsec over TCP encapsulation (TCP header + trailer). */
  SshUInt8 tcp_encaps_len;
#endif /* SSH_IPSEC_TCPENCAP */

  /* Padding boundary (multiple). */
  SshUInt8 pad_boundary;
} SshFastpathTransformContextStruct;


/* Allocates a transform context for the transform.  This maintains a
   cache of recently used encryption context (a simple hash table is used
   to find the appropriate context efficiently).  This also keeps the
   context on an LRU list, and if the context is not found, the least recently
   used entry is taken from the LRU list.  Entries that are currently being
   used are not on the LRU list.  This returns the allocated transform
   context, or NULL if all transform contexts are currently in use. */
SshFastpathTransformContext
ssh_fastpath_get_transform_context(SshFastpath fastpath,
                                   SshEngineTransformRun trr,
                                   SshEnginePacketContext pc,
                                   Boolean for_output,
                                   Boolean inner_is_ipv6,
                                   Boolean outer_is_ipv6);

/* Returns the transform context to the system for reuse.  The
   transform context is returned to the cache of available contexts,
   and may be reused if another packet is received for the same
   security association.  All allocated contexts must be released
   after they have been used.  This marks the context as not in use,
   and puts it at the head of the LRU list. */
void ssh_fastpath_release_transform_context(SshFastpath fastpath,
                                            SshFastpathTransformContext tc);

/* Uninit the transform context by freeing memory allocated for it. */
void ssh_fastpath_uninit_transform_context(SshFastpathTransformContext tc);

/* Adds the given transform context at the tail of the LRU list.  This
   means that it will be a preferred candidate for reuse.  This
   function is also called from initialization code. */
void ssh_fastpath_tc_lru_insert_tail(SshFastpath fastpath,
                                     SshFastpathTransformContext tc);

/* Adds the tc to the hash table.  This funtion is also called from
   initialization code. */
void ssh_fastpath_tc_hash_insert(SshFastpath fastpath,
                                 SshFastpathTransformContext tc);



/* **************** Transform Execution ***********************/


/* Maximum size of the combined prefix in IPSEC transforms.  The
   prefix includes any prefix space required for NAT-T, AH, ESP, UDP,
   IPCOMP header, UDP+L2TP, and IP-in-IP.  The IPv6 header is 20 bytes
   longer than the default IPv4 header, hence the 20 byte increase. */
#if defined (WITH_IPV6)
#define SSH_ENGINE_MAX_TRANSFORM_PREFIX 180
#else /* WITH_IPV6 */
#define SSH_ENGINE_MAX_TRANSFORM_PREFIX 160
#endif /* WITH_IPV6 */

#ifdef SSHDIST_L2TP
/* Some PPP DLL protocol numbers for L2TP. */
#define SSH_PPP_PROTO_IP        0x0021
#define SSH_PPP_PROTO_IPV6      0x0057
#endif /* SSHDIST_L2TP */

#ifdef SSHDIST_IPSEC_NAT
/* Performs the NAT transform defined by the flow for the
   PacketContext 'pc'. 'pc'->flags is used for tracking
   if the NAT is already done, if so, then TRUE is
   returned without a "second NAT" being applied. */
Boolean ssh_fastpath_transform_nat(SshFastpath fastpath,
                                   SshEnginePacketContext pc,
                                   Boolean forward);
#endif /* SSHDIST_IPSEC_NAT */

/* Implements outgoing IPSEC transforms for outgoing packets.  This
   function implements AH, ESP, IPCOMP, L2TP, NAT Traversal, and
   IP-in-IP (for tunnel mode) transforms. */








void ssh_fastpath_transform_out(SshFastpath fastpath,
                                SshEnginePacketContext pc,
                                SshEngineTransformRun trr,
                                SshFastpathTransformCB callback,
                                void *context);

/* Performs inbound processing for incoming IPSEC packets and ICMPs
   related to them.  Note that the definition of an IPSEC packet is
   relatively broad here; it also includes UDP-encapsulated IPSEC
   packets (NAT Traversal packets and/or L2TP packets).  Basically
   anything that needs to have IPSEC transforms performed on it comes
   here, as do error ICMPs related to such packets.  This function
   performs any required encryption and/or message authentication
   processing, as well as replay prevention (NAT Traversal, AH, ESP,
   IPCOMP, L2TP, and IP-in-IP for tunnel mode are all implemented by
   this function.  When this is
   called, the packet has already gone throgh basic sanity checks, and
   we know that it is at least hdrlen+8 bytes long.  The packet should
   also already have gone through reassembly (unless policy manager
   supplied incorrect configuration data to the engine). */
void ssh_fastpath_transform_in(SshFastpath fastpath,
                               SshEnginePacketContext pc,
                               SshEngineTransformRun trr,
                               SshFastpathTransformCB callback,
                               void *context);

/* Decrypts the ESP packet and validates the ESP packet's ICV when combined
   mode ciphers are used. */
Boolean
ssh_fastpath_esp_transform_combined_in(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len,
        Boolean *icv_failure);

/* Encrypts the ESP packet and computes the ICV for the ESP packet when
   combined mode ciphers are used. */
Boolean
ssh_fastpath_esp_transform_combined_out(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len,
        size_t icv_offset);

/* Decrypts the ESP packet when normal mode ciphers are used. Function returns
   TRUE on success, and FALSE on error, in which case `pc->pp' has been freed.
 */
Boolean
ssh_fastpath_esp_transform_in(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len);

/* Encrypts the ESP packet when normal mode ciphers are used. Function returns
   TRUE on success, and FALSE on error, in which case `pc->pp' has been freed.
 */
Boolean
ssh_fastpath_esp_transform_out(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t crypt_offset,
        size_t crypt_len);

/* Compute ICV and copy it into the ESP packet. Function returns TRUE on
   success, and FALSE on error, in which case `pc->pp' has been freed. */
Boolean
ssh_fastpath_esp_compute_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t mac_offset,
        size_t mac_len,
        size_t icv_offset);

/* Verify ICV for the ESP packet. Function returns FALSE if an error occurs.
   Argument 'icv_failure' is set to FALSE if there was error during computation
   and in which case pc->pp has been freed. Argument 'icv_failure' is set to
   TRUE if received ICV from packet has not valid and in which case pc->pp has
   not been freed. In successful case function returns TRUE.
 */
Boolean
ssh_fastpath_esp_verify_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        size_t mac_offset,
        size_t mac_len,
        Boolean *icv_failure);

#ifdef SSH_IPSEC_AH
/* Compute ICV and copy it into the AH packet. Function returns TRUE on
   success, and FALSE on error, in which case `pc->pp' has been freed. */
Boolean
ssh_fastpath_ah_compute_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta,
        size_t mac_offset,
        size_t mac_len,
        size_t icv_offset);

/* Verify ICV for the AH packet. Function returns FALSE if an error occurs.
   Argument 'icv_failure' is set to FALSE if there was error during computation
   and in which case pc->pp has been freed. Argument 'icv_failure' is set to
   TRUE if received ICV from packet has not valid and in which case pc->pp has
   not been freed. In successful case function returns TRUE.
 */
Boolean
ssh_fastpath_ah_verify_icv(
        SshFastpathTransformContext tc,
        SshEnginePacketContext pc,
        SshInt16 len_delta,
        size_t mac_offset,
        size_t mac_len,
        Boolean *icv_failure);

#endif /* SSH_IPSEC_AH */


#ifdef SSHDIST_IPSEC_NAT
/* Performs NAT on either source or destination address and port.  This
   basically just writes the respective IP address and port, and updates
   the header checksum accordingly.  This returns FALSE if an error occurs
   (in which case pc->pp has been freed).

   Requires the following fields to be uptodate:
   - pc->ipproto
   - pc->pp->protocol
   - pc->pp->flags
   - pc->packet_len
*/

Boolean ssh_fastpath_execute_nat(SshEnginePacketContext pc,
                                 Boolean do_src,
                                 SshIpAddr new_ip,
                                 SshUInt16 new_port);
#endif /* SSHDIST_IPSEC_NAT */


#ifdef SSHDIST_IPSEC_IPCOMP
/* Implements IPComp transform for outgoing packets.
   'ipcomp_ofs' is the offset in the packet 'pc->pp' where compression
   should be performed. 'extra' is a buffer of length 'extra_len'
   that should be appended to the payload data in 'pc->pp' before
   compression. This is used when IPComp performed in combination
   with L2TP, the UDP+L2TP+PPP headers are encoded in 'extra' and are
   input to the compression function. It is possible that no IPComp
   operation is performed, the return value of this indicates whether
   compression did succeed. This function does not add an IPComp header
   to the packet. */
SshFastpathTransformIpcompStatus
ssh_fastpath_transform_ipcomp_outbound(SshEnginePacketContext pc,
                                       SshFastpathTransformContext tc,
                                       SshUInt32 ipcomp_ofs,
                                       const unsigned char *extra,
                                       size_t extra_len);

/* Performs inbound processing for the incoming packet. The packet
   length may change after this operation. This should be called after
   any/all AH/ESP processing has been completed. 'ipcomp_ofs' is the offset
   in bytes in the packet where the IPComp header resides. This function
   decompresses the payload data but does not remove the IPComp header
   from the packet. */
SshFastpathTransformIpcompStatus
ssh_fastpath_transform_ipcomp_inbound(SshEnginePacketContext pc,
                                      SshFastpathTransformContext tc,
                                      SshUInt32 ipcomp_ofs);


/* Consults an adaptive algorithm maintained in transform data to find
   out if compression has to be attempted */
SshFastpathTransformIpcompState
ssh_fastpath_ipcomp_state(SshEnginePacketContext pc,
                        SshFastpathTransformContext tc);
#endif /* SSHDIST_IPSEC_IPCOMP */

/* This function executes the transform indicated by pc->transform,
   and when done, calls ssh_engine_packet_continue with
   SSH_ENGINE_RET_ERROR if an error caused pc->pp to become invalid,
   SSH_ENGINE_RET_FAIL on other errors, SSH_ENGINE_RET_SEND to send
   the packet out, SSH_ENGINE_RET_DROP to drop the packet, and may use
   other values defined for the SshEngineActionRet type. */
void ssh_fastpath_execute_transform(SshEnginePacketContext pc);

/* ******************* FlowData object *******************************/
#ifndef FASTPATH_PROVIDES_FLOW

typedef struct SshFastpathFlowDataCacheRec
{
  unsigned char forward_flow_id[SSH_ENGINE_FLOW_ID_SIZE];
  unsigned char reverse_flow_id[SSH_ENGINE_FLOW_ID_SIZE];
  SshUInt32 flow_lru_level;
} SshFastpathFlowDataCacheStruct, *SshFastpathFlowDataCache;

#endif /* !FASTPATH_PROVIDES_FLOW */

typedef struct SshFastpathFlowDataRec
{
  SshEngineFlowDataStruct data[1];

#if defined (SSH_IPSEC_UNIFIED_ADDRESS_SPACE) || defined (KERNEL)
  /* Lock protecting fields of this data structure */
  SshKernelMutexStruct lock;
#endif

  /* Index of the next node in the hash chain.  The node can be on two
     separate hash chains, one for the forward flow id and another for
     the reverse flow id.  The `forward_next' field points to the next
     node when on the freelist. */
  SshUInt32 forward_next;
  SshUInt32 reverse_next;

  /* Next and prev pointers for the flow LRU and the current flow LRU
     level.  The flow LRU list is used to delete old flows when the
     system is out of flow records.  The head of the flow LRU list is
     engine->flow_lru_head[level], and tail is
     engine->flow_lru_tail[level]. */





  SshUInt32 flow_lru_next;
  SshUInt32 flow_lru_prev;

} SshFastpathFlowDataStruct, *SshFastpathFlowData;

/* ******************* NexthopData object ****************************/

typedef struct SshFastpathNextHopDataRec
{
  SshEngineNextHopDataStruct data[1];
} SshFastpathNextHopDataStruct, *SshFastpathNextHopData;

/* ******************* TransformData object **************************/

#ifndef FASTPATH_PROVIDES_TRD

typedef struct SshFastpathTransformDataCacheRec
{
  SshUInt64 transform;
  SshUInt32 spis[6];
  SshUInt32 old_spis[3];
  unsigned char keymat[SSH_IPSEC_MAX_KEYMAT_LEN];
  unsigned char old_keymat[SSH_IPSEC_MAX_KEYMAT_LEN / 2];
  Boolean is_ipv6;
  SshIpAddrStruct own_addr;
  SshIpAddrStruct gw_addr;
  SshUInt16 remote_port;
} SshFastpathTransformDataCacheStruct, *SshFastpathTransformDataCache;

#endif /* !FASTPATH_PROVIDES_TRD */

typedef struct SshFastpathTransformDataRec
{
  SshEngineTransformDataStruct data[1];

#if defined (SSH_IPSEC_UNIFIED_ADDRESS_SPACE) || defined (KERNEL)
  /* Lock protecting fileds of this data structure */
  SshKernelMutexStruct lock;
#endif
} SshFastpathTransformDataStruct, *SshFastpathTransformData;

/* ******************* CPU context ***********************************/
#define SSH_FASTPATH_TAIL_RECURSION_DETECT       0x0001
typedef struct SshFastpathCpuCtxRec
{
  SshUInt32 flags;

  /* Used along with SSH_FASTPATH_FLAG_TAIL_RECURSION_DETECT. */
  SshKernelMutexStruct pkt_list_lock;
  SshEnginePacketContext recursive_pkt_list;
  SshEnginePacketContext recursive_pkt_list_tail;
} SshFastpathCpuCtxStruct, *SshFastpathCpuCtx;

/* ******************* Fastpath object *******************************/


struct SshFastpathRec {
  /** Back pointer to Engine object. */
  SshEngine engine;

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  /** Handle to the accelerated FastPath. */
  SshFastpathAccel accel;

  /** Pointer to accelerated fastpath flow id computation routine. */
  SshFastpathAccelFlowIDCB accel_flow_id_cb;
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  /* The number of CPU's in the system. */
  unsigned int num_cpus;

  /* CPU specific operation data */
  SshFastpathCpuCtx cpu_ctx;
  SshKernelCriticalSectionStruct cpu_ctx_critical_section;

#ifdef SSH_IPSEC_STATISTICS
  /* Global per-CPU array of fastpath statistics for the software fastpath */
  SshFastpathGlobalStats stats;

  /* Critical section for fastpath statistics. */
  SshKernelCriticalSectionStruct stats_critical_section[1];
  Boolean stats_critical_section_initialized;
#endif /* SSH_IPSEC_STATISTICS */

  /* Lock for flow ID hash table */
  SshKernelRWMutexStruct flow_id_hash_table_lock[1];
  Boolean flow_id_hash_table_lock_initialized;

  /* Table sizes of fastpath data objects */
  SshUInt32 flow_table_size;
  SshUInt32 flow_id_hash_size;
  SshUInt32 transform_table_size;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 next_hop_hash_size;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* ***************** Data for flows, transforms, and next hops *************/

#ifndef FASTPATH_PROVIDES_FLOW
  SshFastpathFlowData *flow_data_table_root;

  /* Hash table for flow id nodes.  This is indexed by
     SSH_ENGINE_FLOW_ID_HASH from the flow id, and contains the index
     of the first flow table node on the hash list.  The size of this
     table is flow_table_size.  Each element of these tables points to
     the first entry on a hash list (linked by the `forward_next'
     field for the forward flow id, and by `reverse_next' for the
     reverse flow id).  This table is protected using
     flow_control_table_lock. */
  SshUInt32 **flow_forward_hash_root;
  SshUInt32 **flow_reverse_hash_root;
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_TRD
  SshFastpathTransformData *transform_data_table_root;
#endif /* !FASTPATH_PROVIDES_TRD */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifndef FASTPATH_PROVIDES_NH
  SshFastpathNextHopData *next_hop_data_table_root;
#endif /* !FASTPATH_PROVIDES_NH */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Head and tail pointers for the LRU list of all active flows in
     the system, indexed by the flow's importance (higher values
     signify higher precedence). */




  struct {
    SshUInt32 head, tail;
  } flow_lru[SSH_ENGINE_N_FLOW_LRU_LEVELS];

  /* ***************** Data for reassembly and fragment magic *************/

  /* Lock for the fragment magic and reassembly data structures. */
  SshKernelMutex frag_lock;

  /* Array containing all fragment magic / reassembly entries.  This
     is initialized when the fastpath object is created.  There is no
     freelist for these entries; when the fastpath is created, all
     entries are initialized to bogus values and we depend on it
     simply being too improbable to get a false match (probability is
     on the order of 10^-100, which is much less than the probability
     of random CPU malfunctions). */
  SshFastpathFragEntry frag_table;

  /* Hash table of fragment entries.  Each hash list is chained by
     fe->hash_next. */
  SshFastpathFragEntry *frag_hash;

#if defined (WITH_IPV6)
  /* A running counter for IPv6 fragmentation id's. */
  SshUInt32 frag_id_ctr;
#endif /* WITH_IPV6 */

  /* Total number of fragments in the reassembly data structures. */
  SshUInt32 frag_num_fragments;

  /* Total number of bytes in the reassembly data structures. */
  SshUInt32 frag_num_bytes;

  /* LRU list for all fragment magic / reassembly entries (both those with
     fragments and those without fragments). */
  SshFastpathFragEntry frag_all_lru_head;
  SshFastpathFragEntry frag_all_lru_tail;

  /* LRU list for those fragment magic / reassembly entries that have
     fragments. */
  SshFastpathFragEntry frag_data_lru_head;
  SshFastpathFragEntry frag_data_lru_tail;

  /* Policy for fragment handling in the fastpath */
  SshEngineFragmentPolicy frag_policy;

  SshUInt8 frag_timeout_scheduled : 1; /* Fragment reassembly timeout has
                                          been scheduled. */


  /* ********** Data for transform context handling *************/

  /* Lock for the transform context cache. */
  SshKernelMutex tc_lock;

  /* Critical section for the transform context cache. */
  SshKernelCriticalSectionStruct tc_critical_section[1];
  Boolean tc_critical_section_initialized;

  /* Table of transform contexts.  The transform hash table and LRU list
     are protected by fastpath->tc_critical_section.  (The critical section
     is not held while the transform is actually being used, as only one
     thread can be using the transform context at any given time). */
  SshFastpathTransformContext *tc_table_root;

  /* Array of (fastpath->num_cpus+1) hash tables into transform contexts.
     The size of the each hash table is SSH_ENGINE_MAX_TRANSFORM_CONTEXTS.
     Elements 0,...fastpath->num_cpus-1 of the array are protected by
     fastpath->tc_critical_section, the last element of the array is protected
     by fastpath->tc_lock. */
  SshUInt32 **tc_hash;

  /* Array of (fastpath->num_cpus+1) LRU head and tail pointers for transform
     contexts. Elements 0,...fastpath->num_cpus-1 of the array are protected
     by fastpath->tc_critical_section, the last element of the array is
     protected by fastpath->tc_lock. */
  SshUInt32 *tc_head;
  SshUInt32 *tc_tail;

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  /* Lock for protecting all operations performed for ip payload
     compression */
  SshKernelMutex ipcomp_lock;
  /* IPCOMP buffer cache shared by all IPCOMP associations belonging
     to this engine instance. Access to this freelist is protected by
     ipcomp_buffer_lock */
  SshFastpathIpcompList ipcomp_buf;

#ifdef SSHDIST_ZLIB
  /* A shared buffer cache to implement memory management for zlib
     library. This is also protected by ipcomp_lock */
  SshFastpathIpcompList zlib_buf;
  /* zlib context shared by all transform context using IPComp and
     deflate algorithm */
  SshCompressDeflateContext *zlib_context;
#endif /* SSHDIST_ZLIB */





#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSH_IPSEC_SEND_IS_SYNC
  /* Eliminating recursive ssh_engine_packet_handler() calls from the
     same kernel thread. */

  /* List of kernel thread IDs currently executing in
     ssh_engine_packet_handler() and the directions of their packets.
     Unused slots have the value NULL.  This array is protected by
     engine->pc_lock. */
  void *active_thread_ids[SSH_ENGINE_NUM_CONCURRENT_THREADS];

  /* List of packets from recursive ssh_engine_packet_handler() calls.
     These fields are protected by engine->pc_lock. */
  SshInterceptorPacket recursive_packets_head;
  SshInterceptorPacket recursive_packets_tail;

  /* Send packets */
  SshInterceptorPacket send_packets_head;
  SshInterceptorPacket send_packets_tail;
#endif /* SSH_IPSEC_SEND_IS_SYNC */


  /* ********** Data for implementing engine_fastpath.h macros *************/

#ifndef FASTPATH_PROVIDES_FLOW
  /* Flow cache data used by the FASTPATH_{GET,COMMIT}_FLOW macros. A single
     instance of the type is sufficient since the fastpath API ensures
     that after a call to one of FASTPATH_GET_FLOW macro no other
     fastpath flow data object will be accessed until FASTPATH_COMMIT_FLOW
     or FASTPATH_RELEASE_FLOW is called for the same data object.  */
  SshFastpathFlowDataCacheStruct flow_cache[1];
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_TRD
  /* Transform cache data used by the FASTPATH_{GET,COMMIT}_TRD macros.  A
     single instance of the type is sufficient since the fastpath API
     ensures that after a call to one of FASTPATH_GET_TRD macro no other
     fastpath trd data object will be accessed until FASTPATH_COMMIT_TRD
     or FASTPATH_RELEASE_TRD is called for the same data object */
  SshFastpathTransformDataCacheStruct trd_cache[1];
#endif /* !FASTPATH_PROVIDES_TRD */
 };

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifndef FASTPATH_PROVIDES_NH

/* Macros for accessing next hop data nodes. */
#define SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshFastpathNextHopDataStruct))

#ifdef DEBUG_LIGHT
#define SSH_FASTPATH_GET_NH_DATA(fastpath, idx)                              \
(((idx) >= fastpath->next_hop_hash_size                                      \
 ? ssh_fatal("next hop index out of bounds")                                 \
   , (SshEngineNextHopData)NULL                                              \
 : ((fastpath)->next_hop_data_table_root                                     \
                              [(idx)/SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE]     \
                              [(idx)%SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE].data)))
#else /* DEBUG_LIGHT */
#define SSH_FASTPATH_GET_NH_DATA(fastpath, idx)                              \
(((fastpath)->next_hop_data_table_root                                       \
                              [(idx)/SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE]     \
                              [(idx)%SSH_ENGINE_NH_D_TABLE_BLOCK_SIZE].data))
#endif /* DEBUG_LIGHT */
#endif /* !FASTPATH_PROVIDES_NH */
#endif /*! SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifndef FASTPATH_PROVIDES_TRD
/* How many data transforms can be held per block? */
#define SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshFastpathTransformDataStruct))

/* Convenience macro for accessing the 2d transform array */
#define SSH_FASTPATH_GET_TRD_UNWRAPPED(fastpath, idx)     \
(((idx) >= (fastpath)->transform_table_size               \
  ? ssh_fatal("transform index out of bounds")            \
  , (SshEngineTransformData)NULL                          \
  : (((fastpath)->transform_data_table_root              \
       [(idx) / SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE]         \
       [(idx) % SSH_ENGINE_TR_D_TABLE_BLOCK_SIZE].data))))
#endif /* !FASTPATH_PROVIDES_TRD */


#ifndef FASTPATH_PROVIDES_FLOW
/* A convenience macro for the size of flow table array blocks. */
#define SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshFastpathFlowDataStruct))

/* Macro for fetching flow "flow_index" */
#ifdef DEBUG_LIGHT
#define SSH_FASTPATH_GET_FLOW_DATA(fastpath, flow_index)                   \
(((flow_index) >= (fastpath)->flow_table_size                              \
  ? ssh_fatal("flow index 0x%lx out of bounds", (unsigned long) flow_index)\
    , (SshEngineFlowData)NULL                                              \
  : (fastpath)->flow_data_table_root                                       \
                    [(flow_index) / SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE]    \
                    [(flow_index) % SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE].data))
#else /* DEBUG_LIGHT */
#define SSH_FASTPATH_GET_FLOW_DATA(fastpath, flow_index)                    \
   (((fastpath)->flow_data_table_root                                       \
                    [(flow_index) / SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE]     \
                    [(flow_index) % SSH_ENGINE_FLOW_D_TABLE_BLOCK_SIZE].data))
#endif /* DEBUG_LIGHT */
#endif /* !FASTPATH_PROVIDES_FLOW */

/* Macro for the size of the flow hash */
#define SSH_ENGINE_FLOW_HASH_BLOCK_SIZE \
(SSH_ENGINE_MAX_MALLOC / sizeof(SshUInt32))

#ifndef FASTPATH_ACCELERATOR_CONFIGURED
#define FP_ASSERT_LOCKED(fastpath)
#define FP_LOCK_READ(fastpath)
#define FP_LOCK_WRITE(fastpath)
#define FP_UNLOCK_READ(fastpath)
#define FP_UNLOCK_WRITE(fastpath)

#else /* FASTPATH_ACCELERATOR_CONFIGURED */

#define FP_ASSERT_LOCKED(fastpath)                                            \
  do {                                                                        \
 ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);\
   } while (0)

#define FP_LOCK_READ(fastpath)                                          \
  do {                                                                  \
     ssh_kernel_mutex_lock(fastpath->engine->flow_control_table_lock);  \
   } while (0)

#define FP_LOCK_WRITE(fastpath)                                          \
  do {                                                                   \
     ssh_kernel_mutex_lock(fastpath->engine->flow_control_table_lock);   \
   } while (0)

#define FP_UNLOCK_READ(fastpath)                                         \
  do {                                                                   \
     ssh_kernel_mutex_unlock(fastpath->engine->flow_control_table_lock); \
   } while (0)

#define FP_UNLOCK_WRITE(fastpath)                                        \
  do {                                                                   \
     ssh_kernel_mutex_unlock(fastpath->engine->flow_control_table_lock); \
   } while (0)
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */


#ifdef FASTPATH_PROVIDES_FLOW

#define FP_GET_FLOW(fastpath, flow_index)                                \
    fastpath_accel_get_flow((fastpath)->accel, flow_index)
#define FP_GET_FLOW_UNLOCKED(fastpath, flow_index)                       \
    fastpath_accel_get_flow((fastpath)->accel, flow_index)
#define FP_GET_FLOW_LOCK_HASH(fastpath, flow_index)                      \
    fastpath_accel_get_flow((fastpath)->accel, flow_index)

#define FP_COMMIT_FLOW(fastpath, flow_index, flow)                       \
    fastpath_accel_commit_flow((fastpath)->accel, flow_index, flow)
#define FP_COMMIT_FLOW_UNLOCK_HASH(fastpath, flow_index, flow)           \
    fastpath_accel_commit_flow((fastpath)->accel, flow_index, flow)
#define FP_COMMIT_FLOW_UNLOCK_HASH_READ(fastpath, flow_index, flow)      \
    fastpath_accel_commit_flow((fastpath)->accel, flow_index, flow)

#define FP_RELEASE_FLOW(fastpath, flow_index)                            \
    fastpath_accel_release_flow((fastpath)->accel, flow_index)
#define FP_RELEASE_FLOW_UNLOCK_HASH(fastpath, flow_index)                \
    fastpath_accel_release_flow((fastpath)->accel, flow_index)

#else /* FASTPATH_PROVIDES_FLOW */

SshEngineFlowData
swi_fastpath_get_flow_lock(SshFastpath fastpath,
                           SshUInt32 flow_index,
                           Boolean lock_flow,
                           Boolean lock_hash_table);

/** Get a flow, no locking performed. */
#define FP_GET_FLOW_UNLOCKED(fastpath, flow_index)                      \
    swi_fastpath_get_flow_lock(fastpath, flow_index, FALSE, FALSE)

/** Get a flow, locks the flow but not the flow hash table. */
#define FP_GET_FLOW(fastpath, flow_index)                               \
    swi_fastpath_get_flow_lock(fastpath, flow_index, TRUE, FALSE)

/** Get a flow, locks the flow and the flow hash table. */
#define FP_GET_FLOW_LOCK_HASH(fastpath, flow_index) \
    swi_fastpath_get_flow_lock(fastpath, flow_index, TRUE, TRUE)

/** Commit the flow, flow must be locked, the flow hash table is not locked. */
#define FP_COMMIT_FLOW(fastpath, flow_index, flow)          \
do {                                                               \
    ssh_kernel_mutex_unlock(&((SshFastpathFlowData)(flow))->lock); \
   } while (0)

/** Commit the flow, the flow and the flow hash table must both be locked. */
#define FP_COMMIT_FLOW_UNLOCK_HASH(fastpath, flow_index, flow)         \
do {                                                                   \
  ssh_kernel_mutex_unlock(&((SshFastpathFlowData)(flow))->lock);       \
  ssh_kernel_rw_mutex_unlock_write(fastpath->flow_id_hash_table_lock); \
   } while (0)

/** Commit the flow, the flow and the flow hash table must both be locked. */
#define FP_COMMIT_FLOW_UNLOCK_HASH_READ(fastpath, flow_index, flow)        \
do {                                                                       \
  ssh_kernel_mutex_unlock(&((SshFastpathFlowData)(flow))->lock);           \
  ssh_kernel_rw_mutex_unlock_read(fastpath->flow_id_hash_table_lock);      \
   } while (0)

/** Release the flow. The flow is locked, the flow hash table is not locked. */
#define FP_RELEASE_FLOW(fastpath, flow_index)                              \
do {                                                                       \
  SshFastpathFlowData _flow_=                                              \
     (SshFastpathFlowData) FP_GET_FLOW_UNLOCKED(fastpath, flow_index);     \
  ssh_kernel_mutex_unlock(&_flow_->lock);                                  \
  (void)_flow_;                                                            \
   } while (0)

/** Release the flow, the flow and the flow hash table must both be locked. */
#define FP_RELEASE_FLOW_UNLOCK_HASH(fastpath, flow_index)                   \
do {                                                                        \
  SshFastpathFlowData _flow_ =                                              \
     (SshFastpathFlowData) FP_GET_FLOW_UNLOCKED(fastpath,flow_index);       \
  ssh_kernel_mutex_unlock(&_flow_->lock);                                   \
  ssh_kernel_rw_mutex_unlock_write(fastpath->flow_id_hash_table_lock);      \
  (void)_flow_;                                                            \
   } while (0)



/** Function declarations for FASTPATH_*_FLOW macro sw implementations. */

SshEngineFlowData
sw_fastpath_get_flow(SshFastpath fastpath, SshUInt32 flow_index,
                     Boolean ronly);

void
sw_fastpath_commit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                        SshEngineFlowData data);

void
sw_fastpath_uninit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                        SshEngineFlowData data);

void
sw_fastpath_release_flow(SshFastpath fastpath, SshUInt32 flow_index);

#endif /* FASTPATH_PROVIDES_FLOW */


#ifdef FASTPATH_PROVIDES_TRD

#define FP_GET_TRD(fastpath, trd_index) \
    fastpath_accel_get_trd((fastpath)->accel, trd_index)
#define FP_GET_TRD_UNLOCKED(fastpath, trd_index) \
    fastpath_accel_get_trd((fastpath)->accel, trd_index)

#define FP_COMMIT_TRD(fastpath, trd_index, trd) \
    fastpath_accel_commit_trd((fastpath)->accel, trd_index, trd)

#define FP_RELEASE_TRD(fastpath, trd_index) \
    fastpath_accel_release_trd((fastpath)->accel, trd_index)

#else /* FASTPATH_PROVIDES_TRD */

/** Get TRD. */
SshEngineTransformData swi_fastpath_get_trd_lock(SshFastpath fastpath,
                                                 SshUInt32 trd_index,
                                                 Boolean lock);

/** Get a TRD, no locking performed. */
#define FP_GET_TRD_UNLOCKED(fastpath, trd_index) \
         swi_fastpath_get_trd_lock(fastpath, trd_index, FALSE)
/** Get a TRD and lock it. */
#define FP_GET_TRD(fastpath, trd_index)    \
         swi_fastpath_get_trd_lock(fastpath, trd_index, TRUE)
/** Commit the TRD, the TRD must be locked. */
#define FP_COMMIT_TRD(fastpath, trd_index, trd) \
        ssh_kernel_mutex_unlock(&((SshFastpathTransformData)(trd))->lock)
/** Release the TRD, the TRD must be locked. */
#define FP_RELEASE_TRD(fastpath, trd_index)                                   \
 do {                                                                         \
  SshFastpathTransformData _trd;                                              \
  _trd = (SshFastpathTransformData)FP_GET_TRD_UNLOCKED(fastpath, trd_index);  \
  ssh_kernel_mutex_unlock(&_trd->lock);                                       \
 } while (0)


/** Function declarations for FASTPATH_*_TRD macro sw implementations. */

SshEngineTransformData
sw_fastpath_get_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    Boolean ronly, Boolean init);

void
sw_fastpath_commit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                       SshEngineTransformData data);

void
sw_fastpath_uninit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                       SshEngineTransformData data);

void
sw_fastpath_release_trd(SshFastpath fastpath, SshUInt32 trd_index);

#endif /* FASTPATH_PROVIDES_TRD */

#ifdef FASTPATH_PROVIDES_NH

#define FP_GET_NH(fastpath, nh_index) \
    fastpath_accel_get_nh((fastpath)->accel, nh_index)
#define FP_COMMIT_NH(fastpath, nh_index, nh) \
    fastpath_accel_commit_nh((fastpath)->accel, nh_index, nh)
#define FP_RELEASE_NH(fastpath, nh_index) \
    fastpath_accel_release_nh((fastpath)->accel, nh_index)

#else /* FASTPATH_PROVIDES_NH */

#define FP_GET_NH(fastpath, nh_index) \
    SSH_FASTPATH_GET_NH_DATA((fastpath), (nh_index))
#define FP_COMMIT_NH(fastpath, flow_index, flow)
#define FP_RELEASE_NH(fastpath, flow_index)


/** Function declarations for FASTPATH_*_NH macro sw implementations. */

SshEngineNextHopData
sw_fastpath_get_nh(SshFastpath fastpath, SshUInt32 nh_index, Boolean ronly);

void
sw_fastpath_commit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                      SshEngineNextHopData nh);

void
sw_fastpath_release_nh(SshFastpath fastpath, SshUInt32 nh_index);

#endif /* FASTPATH_PROVIDES_NH */

/** Updates the transform context for the given SA, if any.  This
    should be called whenever the IP addresses or NAT-T remote port in a
    security association changes. The new addresses and remote NAT-T port
    are provided by 'local_ip', 'remote_ip', and 'natt_port'.
    The remaining paraters are provided to look up the correct transform
    context. */
void
ssh_fastpath_update_sa_tc(SshFastpath fastpath, SshUInt64 transform,
                          const unsigned char *keymat,
                          SshUInt32 ah_spi, SshUInt32 esp_spi,
                          Boolean for_output, Boolean ipv6,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshUInt16 remote_port);


/** Destroys the transform context for the given SA, if any.  This
    should be called whenever a security association might become
    invalid (i.e., when a transform is destroyed, when the outbound
    direction is rekeyed, when rekeyed inbound SA expires, or when old
    rekeyed inbound SA is still valid when a new inbound rekey
    occurs). */
void
ssh_fastpath_destroy_sa_tc(SshFastpath fastpath, SshUInt64 transform,
                           const unsigned char *keymat,
                           SshUInt32 ah_spi, SshUInt32 esp_spi,
                           Boolean for_output, Boolean ipv6);


#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
/** Processes a TCP/IP packet for a flow.  This expects to be called with
    engine->flow_table_lock held protecting the tcpdata. */
SshEngineProtocolMonitorRet ssh_engine_tcp_packet(SshEngineFlowData flow,
                                                  SshEnginePacketContext pc);
/** Processes a UDP packet for a flow.  This expects to be called with
    engine->flow_table_lock held protecting the udpdata. */
SshEngineProtocolMonitorRet ssh_engine_udp_packet(SshEngineFlowData flow,
                                                  SshEnginePacketContext pc);

/** Processes a ICMP packet for a flow.  This expects to be called with
    engine->flow_table_lock held protecting the udpdata. */
SshEngineProtocolMonitorRet ssh_engine_icmp_packet(SshEngineFlowData flow,
                                                   SshEnginePacketContext pc);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

/** Return appropriate LRU level for a TCP flow based on TCP state. */
int
ssh_engine_tcp_lru_level(SshEngineFlowData flow);

#ifdef FASTPATH_PROVIDES_LRU_FLOWS
SshUInt32
fastpath_get_lru_flow(SshFastpath fastpath, SshUInt32 lru_level);

void
fastpath_bump_lru_flow(SshFastpath fastpath, SshUInt32 flow_index);
#endif /* FASTPATH_PROVIDES_LRU_FLOWS */


SshEngineFlowData
fastpath_sw_lookup_flow(SshFastpath fastpath, SshEnginePacketContext pc);

Boolean
fastpath_sw_init_flows(SshFastpath fastpath);

void
fastpath_sw_uninit_flows(SshFastpath fastpath);

SshEngineFlowData
fastpath_lookup_flow(SshFastpath fastpath, SshEnginePacketContext pc);

void fastpath_fragmagic_uninit(SshFastpath fastpath);

/* Decrement the packet time to live field. Returns FALSE if packet should
   be dropped. */
Boolean fastpath_decrement_ttl(SshEnginePacketContext pc);

SshEnginePacketCorruption
fastpath_packet_context_is_sane(SshEngine engine,
                                SshInterceptorProtocol proto,
                                SshInterceptorPacket pp,
                                const SshEnginePacketContext pc,
                                SshUInt32 *option_ret);

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
   this function returns FALSE, and fill appropriate auding information
   into packet context. */
Boolean
fastpath_packet_context_pullup(SshEngine engine,
                               SshEnginePacketContext pc,
                               SshEnginePacketData pd);


#ifdef FASTPATH_ACCELERATOR_CONFIGURED
/* Function that is called whenever a packet is received from the accelerated
   fastpath. */
void
software_fastpath_packet_handler(SshEngine engine,
                                 SshEnginePacketContext pc,
                                 SshEngineActionRet input_state,
                                 SshEngineActionRet return_state);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

/* Function that is called whenever a packet is received from the
   interceptor.  This function will eventually free `pp', either by
   calling ssh_interceptor_packet_free on the packet or by passing it
   to the ssh_interceptor_send function.  Note that this function may
   be called asynchronously, concurrently with any other functions
   (including itself).

   When a packet is passed to this callback, the `pp->flags' field may
   contain arbitrary flags in the bits reserved for the interceptor
   (mask 0x000000ff).  This callback is not allowed to modify any of
   those bits; they must be passed intact to ssh_interceptor_send or
   ssh_interceptor_packet_free.  Any other bits (mask 0xffffff00) will
   be zero when the packet is sent to this callback; those bits may be
   used freely by this callback.  They are not used by the interceptor. */
void fastpath_packet_callback(SshInterceptorPacket pp, void *context);

/* Starts packet processing on the fastpath. This internal function handles
   recursive calls. It is used for starting packet processing and for
   restarting trigger packet processing. */
SSH_FASTTEXT
void fastpath_packet_handler(SshEngine engine, SshInterceptorPacket pp,
                             SshUInt32 tunnel_id,
                             SshUInt32 prev_transform_index,
                             Boolean is_recursive);

#ifdef SSH_IPSEC_STATISTICS
/* Update counters (both global engine counters and flow counters) as
   indicated by pc->stat_vec. */
void
fastpath_update_statistics_counters(SshFastpath fastpath,
                                    SshEnginePacketContext pc);
#endif /* SSH_IPSEC_STATISTICS */

/* ********************************************************************
 * Flow id computation.  Most of the relevant code is in
 * fastpath_flow_id.c.
 * ********************************************************************/

/** Computes a flow id from the packet.  The computed flow id is 16 bytes
    (128 bits), hashed from various fields of the packet.  This also returns
    hashvalue, which is a 32-bit hash value computed from the flow id.

    If `reverse' is true, this creates the flow id for the reverse direction.

    @return
    This returns TRUE if flow id computation was successful.  This
    returns FALSE if an error occurred, in which case pp is already
    freed when this returns. */
Boolean fastpath_compute_flow_id(SshFastpath fastpath,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 SshUInt32 tunnel_id,
                                 unsigned char *flow_id);


#endif /* FASTPATH_SWI_H */
