/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to implement IPsec and other transforms for incoming packets.

   Note : When decapsulating the headers in a packet, the offsets of each
   header must be computed from parsing the packet and not using the
   offsets in the SshFastpathTransformContext data type. For example, the
   IPComp header may or may not be present in a packet whose transform has
   IPComp enabled. Similarly in MOBIKE scanarios we must be able to
   decapsulate packets regardless of whether they have a NAT-T header or
   not. Hence you must not use any of the fields such as tc->esp_ofs,
   tc->l2tp_ofs etc. for finding the offset of a encapsulation header.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSHDIST_L2TP
#include "sshl2tp_parse.h"
#endif /* SSHDIST_L2TP */

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformIn"


/************************** Internal definitions *****************************/

/* Structure describing a 64 bit integer. We cannot use 'SshUInt64'
   type since it is not guarenteed to be 64 bits on all platforms. */
typedef struct SshUInt64Rec
{
  SshUInt32 high;
  SshUInt32 low;
} SshUInt64Struct;

#define SSH_UINT64_GE(a, b)                                     \
  ((a.high > b.high) || (a.high == b.high && a.low > b.low))
#define SSH_UINT64_GEQ(a, b)                                    \
  ((a.high > b.high) || (a.high == b.high && a.low >= b.low))
#define SSH_UINT64_LE(a, b)                                     \
  ((a.high < b.high) || (a.high == b.high && a.low < b.low))
#define SSH_UINT64_LEQ(a, b)                                    \
  ((a.high < b.high) || (a.high == b.high && a.low <= b.low))

#define SSH_UINT64_ADD(c, a, b)                                         \
  do { SshUInt32 __temp; __temp = a.low + b.low;                        \
    c.high = (__temp < a.low) ? a.high + b.high + 1 : a.high + b.high;  \
    c.low = __temp; } while(0)

#define SSH_UINT64_ADD32(c, a, b)                       \
  do { SshUInt32 __temp; __temp = a.low + b;            \
    c.high = (__temp < a.low) ? a.high + 1 : a.high;    \
    c.low = __temp; } while(0)

/* This assumes 'a' is larger (as a 64 bit integer) than 'b' */
#define SSH_UINT64_SUB(c, a, b)                                         \
  do { SshUInt32 __temp; __temp = a.low - b.low;                        \
    c.high = (b.low <= a.low) ? a.high - b.high : a.high - b.high - 1;  \
    c.low = __temp; } while(0)


/* Utility function for failing inbound transform execution. This updates
   statistics and completes transform execution for the packet. */
static void
fastpath_transform_in_fail(SshFastpath fastpath,
                           SshEnginePacketContext pc,
                           SshEngineActionRet ret)
{
  SSH_ASSERT(pc != NULL);

  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_DROP;

  if (ret == SSH_ENGINE_RET_FAIL)
    SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_TRANSFORMDROP);
  else if (ret == SSH_ENGINE_RET_ERROR)
    SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);

  if (pc->u.flow.tc)
    ssh_fastpath_release_transform_context(fastpath, pc->u.flow.tc);
  (*pc->u.flow.tr_callback)(pc, ret, pc->u.flow.tr_context);
  return;

}


/************* Forward declarations of inbound transform handlers ************/

#ifdef SSHDIST_IPSEC_HWACCEL
/* Perform inbound IPsec transform using hw acceleration. */
static void
fastpath_transform_in_hw(SshFastpath fastpath,
                         SshFastpathTransformContext tc,
                         SshEnginePacketContext pc);
#endif /* SSHDIST_IPSEC_HWACCEL */

/* Perform inbound IPsec transform using software. */
static void
fastpath_transform_in_sw(SshFastpath fastpath,
                         SshFastpathTransformContext tc,
                         SshEnginePacketContext pc);

/* Perform common post crypto inbound transform tasks. */
static void
fastpath_transform_in_finish(SshFastpath fastpath,
                             SshEnginePacketContext pc);


/*********************** Inbound transform start *****************************/

/* Performs inbound processing for incoming IPsec packets and ICMPs related
   to them.

   Note that the definition of an IPsec packet is relatively broad here; it
   also includes UDP-encapsulated IPsec packets (NAT Traversal packets and/or
   L2TP packets). Basically anything that needs to have IPsec transforms
   performed on it comes here, as do error ICMPs related to such packets.

   This function performs basic sanity checks and calls the appropriate
   inbound transform handler to do decryption and/or message authentication
   in hardware or software.

   The hardware accelerated combined inbound IPsec transform handler
   internally performs replay prevention and other post crypto tasks and
   completes inbound transform execution for the packet. Note that the
   hardware accelerated combined transform currently can not perform IPcomp
   or L2TP transforms.

   For other inbound transform handlers the post crypto tasks (replay
   prevention, IPcomp, checksum recalculation, L2TP) are performed in the
   common function fastpath_transform_in_finish(). */

void ssh_fastpath_transform_in(SshFastpath fastpath,
                               SshEnginePacketContext pc,
                               SshEngineTransformRun trr,
                               SshFastpathTransformCB callback,
                               void *context)
{
  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Inbound transform processing entered"));
  SSH_DUMP_PACKET(SSH_D_PCKDMP, "Cryptotext: ", pc->pp);

  /* Check for error ICMPs related to the transform. */
  if (pc->ipproto == SSH_IPPROTO_ICMP
#if defined (WITH_IPV6)
      || pc->ipproto == SSH_IPPROTO_IPV6ICMP
#endif /* WITH_IPV6 */
      )
    {




      (*callback)(pc, SSH_ENGINE_RET_FAIL, context);
      return;
    }

  /* Save callback function for later use. */
  pc->u.flow.tr_callback = callback;
  pc->u.flow.tr_context = context;

  pc->u.flow.trr = trr;

  /* Obtain a transform context for the transform.  This may come from
     a cache or might be constructed here. */
  pc->u.flow.tc =
    ssh_fastpath_get_transform_context(fastpath, pc->u.flow.trr, pc, FALSE,
                                       SSH_IP_IS6(&trr->gw_addr),
                                       pc->pp->protocol == SSH_PROTOCOL_IP6);
  if (pc->u.flow.tc == NULL)
    {
      /* Failed to allocate action context. */
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate transform context"));
      goto fail;
    }

  /* Sanity check packet. */
  if (pc->pp->flags & SSH_ENGINE_P_ISFRAG)
    {
      pc->tunnel_id = pc->u.flow.trr->restart_tunnel_id;

      if (pc->transform & SSH_PM_IPSEC_ESP)
        {
          pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_ESP_IN];
          pc->audit.corruption = SSH_PACKET_CORRUPTION_ESP_IP_FRAGMENT;
          goto fail;
        }
#ifdef SSH_IPSEC_AH
      else if (pc->transform & SSH_PM_IPSEC_AH)
        {
          pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_AH_IN];
          pc->audit.corruption = SSH_PACKET_CORRUPTION_AH_IP_FRAGMENT;
          goto fail;
        }
#endif /* SSH_IPSEC_AH */
      else
        pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;
    }

#ifdef SSH_IPSEC_STATISTICS
  /* Update statistics. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESP_IN);
    }
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AH_IN);
    }
#endif /* SSH_IPSEC_AH */
#endif /* SSH_IPSEC_STATISTICS */

  /* Select appropriate inbound transform handler. */
#ifdef SSHDIST_IPSEC_HWACCEL
  if (pc->u.flow.tc->transform_accel
      || pc->u.flow.tc->encmac_accel
      || pc->u.flow.tc->enc_accel
      || pc->u.flow.tc->mac_accel)
    {
      fastpath_transform_in_hw(fastpath, pc->u.flow.tc, pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  fastpath_transform_in_sw(fastpath, pc->u.flow.tc, pc);

  return;

 fail:
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_FAIL);
}


/******************** Inbound transform utility building blocks *************/

/* Datatype for storing packet offsets. */
typedef struct SshFastpathTransformPktOffsetRec
{
  SshUInt32 prefix_ofs;
  SshUInt32 prefix_len;
  SshInt32 natt_len;
  SshUInt16 esp_ofs;
#ifdef SSH_IPSEC_AH
  SshUInt16 ah_ofs;
#endif /* SSH_IPSEC_AH */
  SshUInt16 enc_ofs;
  SshUInt16 mac_ofs;
  SshUInt16 enc_len;
  SshUInt16 mac_len;
} SshFastpathTransformPktOffsetStruct, *SshFastpathTransformPktOffset;


/* Calculate offsets to packet data and check packet length. If this returns
   FALSE the packet is still valid but the length sanity check has failed. */
static Boolean
fastpath_transform_in_calc_pkt_offset(SshFastpathTransformContext tc,
                                      SshEnginePacketContext pc,
                                      SshFastpathTransformPktOffset ofs)
{
  /* Determine the offset of the packet prefix. */
  if (tc->prefix_at_0)
    ofs->prefix_ofs = 0;
  else
    ofs->prefix_ofs = pc->hdrlen;

  /* Determine the packet prefix length and offsets to allow decapsulation
     of a packet regardless if it has or does not have UDP encapsulation.
     The offset values in tc are used for outbound transform execution. In
     inbound transform execution the offsets need to be corrected depending
     whether packet and 'tc' NAT-T status match. */

  /* NATT packet, non-NAT-T tc */
  if (pc->ipproto == SSH_IPPROTO_UDP
      && (pc->transform & SSH_PM_IPSEC_NATT) == 0)
    {
      ofs->natt_len = SSH_UDPH_HDRLEN;;
      ofs->prefix_len = tc->prefix_len + SSH_UDPH_HDRLEN;
      ofs->esp_ofs = tc->esp_ofs + SSH_UDPH_HDRLEN;
#ifdef SSH_IPSEC_AH
      ofs->ah_ofs = tc->ah_ofs + SSH_UDPH_HDRLEN;
#endif /* SSH_IPSEC_AH */
    }
  else if (pc->ipproto != SSH_IPPROTO_UDP
           && (pc->transform & SSH_PM_IPSEC_NATT))
    {
      /* non-NAT-T packet, NAT-T tc */
      ofs->natt_len = 0;
      ofs->prefix_len = tc->prefix_len - SSH_UDPH_HDRLEN;
      ofs->esp_ofs = tc->esp_ofs - SSH_UDPH_HDRLEN;
#ifdef SSH_IPSEC_AH
      ofs->ah_ofs = tc->ah_ofs - SSH_UDPH_HDRLEN;
#endif /* SSH_IPSEC_AH */
    }
  else
    {
      /* Packet matches tc */
      ofs->natt_len = tc->natt_len;
      ofs->prefix_len = tc->prefix_len;
      ofs->esp_ofs = tc->esp_ofs;
#ifdef SSH_IPSEC_AH
      ofs->ah_ofs = tc->ah_ofs;
#endif /* SSH_IPSEC_AH */
    }

  /* Sanity check that the packet is not too short. */
  if (pc->packet_len <= ofs->prefix_ofs + ofs->prefix_len + tc->trailer_len)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
      return FALSE;
    }

  return TRUE;
}

#ifdef SSHDIST_IPSEC_HWACCEL
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/* Remove the NAT-T header from the packet pc->pp. Returns FALSE on failure in
   which case 'pc->pp' is already freed and set to NULL. */
static Boolean
fastpath_transform_remove_natt_header(SshEnginePacketContext pc)
{
  SshUInt16 cks, old_ip_len;
  SshUInt8 old_ipproto;
  unsigned char *ucpw;

  /* Pullup IPv6 or IPv4 header. */
  ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
  if (ucpw == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to pullup IP header"));
      pc->pp = NULL;
      return FALSE;
    }

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      /* Set the new length and next header in IPv6 case. */
      old_ip_len = SSH_IPH6_LEN(ucpw);
      SSH_IPH6_SET_LEN(ucpw, old_ip_len - SSH_UDPH_HDRLEN);
      SSH_IPH6_SET_NH(ucpw, SSH_IPPROTO_ESP);
    }
  else
#endif /* WITH_IPV6 */
    {
      /* Get checksum, protocol and length from pullup packet */
      cks = SSH_IPH4_CHECKSUM(ucpw);
      old_ipproto = SSH_IPH4_PROTO(ucpw);
      old_ip_len = SSH_IPH4_LEN(ucpw);

      /* Set new protocol. */
      SSH_IPH4_SET_PROTO(ucpw, SSH_IPPROTO_ESP);

      /* Decrement the 8 bytes of NATT header from length field. */
      SSH_IPH4_SET_LEN(ucpw, old_ip_len - SSH_UDPH_HDRLEN);

      /* Update IPv4 header checksum. */
      cks = ssh_ip_cksum_update_byte(cks,
                                     SSH_IPH4_OFS_PROTO,
                                     old_ipproto,
                                     SSH_IPPROTO_ESP);
      cks = ssh_ip_cksum_update_short(cks,
                                      SSH_IPH4_OFS_LEN,
                                      old_ip_len,
                                      old_ip_len - SSH_UDPH_HDRLEN);
      SSH_IPH4_SET_CHECKSUM(ucpw, cks);
    }

  /* Delete 8 bytes from pc->pp irrespective of IPv4 or IPv6 */
  if (!ssh_interceptor_packet_delete(pc->pp, pc->hdrlen, SSH_UDPH_HDRLEN))
    {
      pc->pp = NULL;
      return FALSE;
    }

  SSH_DUMP_PACKET(SSH_D_MY + 10, "packet after natt-decapsulation:", pc->pp);

  return TRUE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_HWACCEL */

/* Parse ESP/AH header from packet. On error the caller must do error
   handling according to the returned code. */
static SshEngineActionRet
fastpath_transform_in_parse_hdr(SshFastpathTransformContext tc,
                                SshEnginePacketContext pc,
                                SshFastpathTransformPktOffset ofs)
{
  unsigned char prefix_buf[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  const unsigned char *prefix;
  const unsigned char *ucpw;
#ifdef SSH_IPSEC_AH
  unsigned char zeroicv[32];
#endif /* SSH_IPSEC_AH */

  SSH_ASSERT(ofs->prefix_len <= SSH_ENGINE_MAX_TRANSFORM_PREFIX);

  /* Check if it is necessary to copy the prefix from the packet to local
     buffer. Note that the code here does not examine the L2TP header, which
     could be of variable length (possibly extending beyond tc->prefix_len).
     We refetch a longer prefix in ssh_engine_transform_in_final before we
     start examining the L2TP header. */
  if (ofs->prefix_ofs + ofs->prefix_len > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    {
      ssh_interceptor_packet_copyout(pc->pp, ofs->prefix_ofs, prefix_buf,
                                     ofs->prefix_len);
      prefix = prefix_buf;
    }
  else
    {
      prefix = ssh_interceptor_packet_pullup_read(pc->pp, ofs->prefix_ofs +
                                                  ofs->prefix_len);
      if (prefix == NULL)
        return SSH_ENGINE_RET_ERROR;
      prefix += ofs->prefix_ofs;
    }

  /* Determine the offsets and amounts to decrypt and authenticate, and get
     the sequence number of replay prevention. */
  ofs->enc_len = 0;
  ofs->mac_len = 0;
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      ucpw = prefix + ofs->esp_ofs;
      if (SSH_ESPH_SPI(ucpw) != tc->esp_spi)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("ESP SPI mismatch: packet 0x%lx expected 0x%lx",
                     SSH_ESPH_SPI(ucpw), tc->esp_spi));
          return SSH_ENGINE_RET_FAIL;
        }

      pc->u.flow.seq_num_low = SSH_ESPH_SEQ(ucpw);
      pc->audit.seq = pc->u.flow.seq_num_low;

      ofs->enc_ofs = ofs->prefix_ofs + ofs->esp_ofs + SSH_ESPH_HDRLEN;
      ofs->enc_len = pc->packet_len - ofs->enc_ofs;
#ifdef SSH_IPSEC_AH
      if ((pc->transform & SSH_PM_IPSEC_AH) == 0)
#endif /* SSH_IPSEC_AH */
        ofs->enc_len -= tc->icv_len;

      if (!tc->counter_mode && tc->cipher_block_len != 0 &&
          ofs->enc_len % tc->cipher_block_len != 0)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Encrypted not cipher block multiple"));
          return SSH_ENGINE_RET_FAIL;
        }
      ofs->mac_ofs = ofs->prefix_ofs + ofs->esp_ofs;
      ofs->mac_len = pc->packet_len - ofs->mac_ofs - tc->icv_len;
      pc->u.flow.mac_icv_ofs = pc->packet_len - tc->icv_len;

      /* Copy ICV from the packet. */
      if (tc->icv_len > 0)
        ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs,
                                       pc->u.flow.packet_icv, tc->icv_len);
    }
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      ucpw = prefix + ofs->ah_ofs;
      if (SSH_AHH_SPI(ucpw) != tc->ah_spi)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("AH SPI mismatch: packet 0x%lx expected 0x%lx",
                     SSH_AHH_SPI(ucpw), tc->ah_spi));
          return SSH_ENGINE_RET_FAIL;
        }

      pc->u.flow.seq_num_low = SSH_AHH_SEQ(ucpw);
      pc->audit.seq = pc->u.flow.seq_num_low;

      ofs->mac_ofs = ofs->prefix_ofs + ofs->ah_ofs;
      ofs->mac_len = pc->packet_len - ofs->mac_ofs;
      pc->u.flow.mac_icv_ofs =
        ofs->prefix_ofs + ofs->ah_ofs + SSH_AHH_MINHDRLEN;

      /* Copy ICV from the packet and zero the ICV in the packet. */
      if (!tc->transform_accel && tc->icv_len > 0)
        {
          ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs,
                                         pc->u.flow.packet_icv, tc->icv_len);
          SSH_ASSERT(tc->icv_len <= sizeof(zeroicv));
          memset(zeroicv, 0, tc->icv_len);

          if (!ssh_interceptor_packet_copyin(pc->pp,
                                             pc->u.flow.mac_icv_ofs,
                                             zeroicv, tc->icv_len))
            return SSH_ENGINE_RET_ERROR;
        }
    }
#endif /* SSH_IPSEC_AH */

  /* Determine higher part of sequence number from lower part and
     the present position of the antireplay window. */
  if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
    {
      pc->u.flow.seq_num_high =
        (pc->u.flow.seq_num_low >= pc->u.flow.trr->mycount_low) ?
        pc->u.flow.trr->mycount_high : pc->u.flow.trr->mycount_high + 1;
    }
  else
    {
      pc->u.flow.seq_num_high = 0;
    }

  return SSH_ENGINE_RET_OK;
}

/* Perform preliminary antireplay checks. If this returns FALSE the packet
   is valid but has not passed the antireplay checks. */
static Boolean
fastpath_transform_in_preliminary_antireplay(SshEnginePacketContext pc)
{
  SshUInt64Struct seq, mycount, max, diff;
  unsigned int bit_ofs;

  SSH_ASSERT(pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH));
  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_ANTIREPLAY);

  /* Do preliminary replay prevention screening. */









  mycount.high = pc->u.flow.trr->mycount_high;
  mycount.low = pc->u.flow.trr->mycount_low;
  seq.low = pc->u.flow.seq_num_low;
  seq.high = pc->u.flow.seq_num_high;

  /* Is seq to the left of the window? */
  if (SSH_UINT64_LE(seq, mycount))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Prelim replay prevention check fail"));
      return FALSE;
    }

  /* Check if seq lies inside the replay window */
  SSH_UINT64_ADD32(max, mycount, 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

  if (SSH_UINT64_LE(seq, max) || SSH_UINT64_GE(mycount, max))
    {
      SSH_UINT64_SUB(diff, seq, mycount);
      SSH_ASSERT(diff.high == 0);
      bit_ofs = diff.low;

      SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
      if (pc->u.flow.trr->myreplaymask[bit_ofs / 32] &
          ((SshUInt32) 1 << (bit_ofs & 31)))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Preliminary replay prevention check fail"));
          return FALSE;
        }
    }

  return TRUE;
}

/* Function which should be called if ICV verfication fails. */
static void
fastpath_transform_in_icv_error(SshFastpathTransformContext tc,
                                SshEnginePacketContext pc)
{














  SSH_DEBUG(SSH_D_FAIL, ("ICV check fails"));
  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;

#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
      pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_AH_IN];
      pc->audit.corruption = SSH_PACKET_CORRUPTION_AH_ICV_FAILURE;
    }
  else
#endif /* SSH_IPSEC_AH */
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
      pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_ESP_IN];
      pc->audit.corruption = SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
    }

  /* Assing from-tunnel ID for the audit event. */
  pc->tunnel_id = pc->u.flow.trr->restart_tunnel_id;
  pc->audit.ip_option = 0;
}


/* Computes the ICV in software and verifies it. On error the caller must
   do error handling according to the returned code. */
static SshEngineActionRet
fastpath_transform_in_sw_compute_icv(SshFastpathTransformContext tc,
                                     SshEnginePacketContext pc,
                                     SshUInt16 mac_offset,
                                     SshUInt16 mac_len,
                                     SshInt16 natt_len)
{
  Boolean verify_success = FALSE;
  Boolean icv_failure = FALSE;

  /* Compute MAC for ESP. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      verify_success = ssh_fastpath_esp_verify_icv(tc, pc, mac_offset, mac_len,
                                                   &icv_failure);
    }

#ifdef SSH_IPSEC_AH
  /* Verify ICV for AH. */
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      verify_success = ssh_fastpath_ah_verify_icv(tc, pc, natt_len, mac_offset,
                                                  mac_len, &icv_failure);
    }
#endif /* SSH_IPSEC_AH */

  if (verify_success == FALSE)
    {
      if (icv_failure == TRUE)
        {
          fastpath_transform_in_icv_error(tc, pc);
          return SSH_ENGINE_RET_FAIL;
        }

      return SSH_ENGINE_RET_ERROR;
    }

  return SSH_ENGINE_RET_OK;
}


static Boolean
fastpath_transform_in_perform_antireplay(SshEnginePacketContext pc)
{
  SshFastpathTransformContext tc = pc->u.flow.tc;
  SshFastpath fastpath = pc->engine->fastpath;
  SshEngineTransformData trd;
  SshEngineTransformRun trr;
  SshUInt32 *replay_window;
  SshPmTransform transform;
  Boolean rekeyold;
  SshUInt64Struct seq, replay_offset, max, diff, temp;
  unsigned int bit_ofs;

  trr = pc->u.flow.trr;
  transform = pc->transform;
  seq.high = 0;
  seq.low = pc->u.flow.seq_num_low;

  /* Update replay prevention information. */
  if (transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH))
    {
      FP_LOCK_WRITE(fastpath);

      trd = FP_GET_TRD(fastpath, pc->transform_index);
      if (trd == NULL)
        {
          /* Transform generation mismatch. */
          FP_RELEASE_TRD(fastpath, pc->transform_index);
          goto fail;
        }

      if (transform & SSH_PM_IPSEC_ANTIREPLAY)
        {
          /* Determine whether we are using old info or new info.
             This code also checks that the transform is still the
             same transform (SPIs have not changed). */
#ifdef SSH_IPSEC_AH
          if (transform & SSH_PM_IPSEC_AH)
            {
              if (trd->spis[SSH_PME_SPI_AH_IN] == tc->ah_spi)
                {
                  rekeyold = FALSE;
                }
              else if (trd->old_spis[SSH_PME_SPI_AH_IN] == tc->ah_spi)
                {
                  rekeyold = TRUE;
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("AH spi mismatch in trd antireplay"));
                  goto fail;
                }
            }
          else
#endif /* SSH_IPSEC_AH */
            {
              if (trd->spis[SSH_PME_SPI_ESP_IN] == tc->esp_spi)
                {
                  rekeyold = FALSE;
                }
              else if (trd->old_spis[SSH_PME_SPI_ESP_IN] == tc->esp_spi)
                {
                  rekeyold = TRUE;
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("ESP spi mismatch in trd antireplay"));
                  goto fail;
                }
            }

          /* Read up-to-date anti-replay information from trd. */
          if (rekeyold)
            {
              replay_offset.high = trd->old_replay_offset_high;
              replay_offset.low = trd->old_replay_offset_low;
              replay_window = trd->old_replay_mask;
            }
          else
            {
              replay_offset.high = trd->replay_offset_high;
              replay_offset.low = trd->replay_offset_low;
              replay_window = trd->replay_mask;
            }

          if (transform & SSH_PM_IPSEC_LONGSEQ)
            {
              /* Determine seq_high from seq_low and the present position
                 of the antireplay window. */
              seq.high = (seq.low >= replay_offset.low) ? replay_offset.high :
                replay_offset.high + 1;
            }
          else
            {
              seq.high = 0;
            }

          /* Recheck that seq is not to the left of the window */
          if (SSH_UINT64_LE(seq, replay_offset))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Replay prevention recheck fail"));
              trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
              if (transform & SSH_PM_IPSEC_AH)
                {
                  pc->audit.corruption
                    = SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
                  pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
                }
              else
#endif /* SSH_IPSEC_AH */
                {
                  pc->audit.corruption =
                    SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
                  pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
                }
              pc->tunnel_id = trr->restart_tunnel_id;
              pc->audit.ip_option = 0;
              goto fail;
            }

          SSH_UINT64_ADD32(max, replay_offset,
                           32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

          /* Recheck that seq does not lie in the replay window bit field */
          if (SSH_UINT64_LE(seq, max) || SSH_UINT64_GE(replay_offset, max))
            {
              SSH_UINT64_SUB(diff, seq, replay_offset);
              SSH_ASSERT(diff.high == 0);
              bit_ofs = diff.low;

              SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

              if (replay_window[bit_ofs / 32] &
                  ((SshUInt32) 1 << (bit_ofs & 31)))
                {
                  SSH_DEBUG(SSH_D_FAIL,("Replay prevention recheck fail"));
                  trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
                  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
                  if (transform & SSH_PM_IPSEC_AH)
                    {
                      pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
                      pc->audit.corruption =
                        SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
                    }
                  else
#endif /* SSH_IPSEC_AH */
                    {
                      pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
                      pc->audit.corruption =
                        SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
                    }
                  pc->tunnel_id = trr->restart_tunnel_id;
                  pc->audit.ip_option = 0;
                  goto fail;
                }
            }

          /* Check whether we need to shift the replay window. Note that
             we must check that replay_offset does not wrap around when
             we add to it. */
          if (SSH_UINT64_GEQ(seq, max) && SSH_UINT64_LE(replay_offset, max))
            {
              SshUInt32 *words, diff_words = 0;
              unsigned int words_to_keep, i;

              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Old replay window"),
                                (unsigned char *)replay_window,
                                4 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

              /* We need to shift the window.  We always shift in
                 multiples of 32 bits to improve performance. The goal
                 is to bring the bit position holding the new packet
                 into the last word of the array. This also improves
                 performance by causing this code to be executed for
                 every 32th packet only. */
              SSH_UINT64_SUB(diff, seq, max);
              SSH_UINT64_ADD32(diff, diff, 1);

              if (diff.high)
                {
                  words_to_keep = 0;
                }
              else
                {
                  /* Compute the number of words the window is to move. */
                  diff_words = (diff.low + 31) / 32;
                  /* Compute the number of words to keep in the window. */
                  if (diff_words >= SSH_ENGINE_REPLAY_WINDOW_WORDS)
                    words_to_keep = 0;
                  else
                    words_to_keep =
                      SSH_ENGINE_REPLAY_WINDOW_WORDS - diff_words;
                }

              /* Now update the window. */
              words = replay_window;
              for (i = 0; i < words_to_keep; i++)
                words[i] = words[i + diff_words];
              for (i = words_to_keep; i < SSH_ENGINE_REPLAY_WINDOW_WORDS; i++)
                words[i] = 0;

              diff.low = diff_words * 32;
              SSH_UINT64_ADD(replay_offset, replay_offset, diff);

              SSH_UINT64_ADD32(temp, replay_offset,
                               32 * SSH_ENGINE_REPLAY_WINDOW_WORDS - 32);
              SSH_ASSERT(SSH_UINT64_LEQ(temp, seq));

              SSH_UINT64_ADD32(temp, replay_offset,
                               32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
              SSH_ASSERT(SSH_UINT64_GE(temp, seq));

              SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                                ("Updated replay window"),
                                (unsigned char *)replay_window,
                                4 * SSH_ENGINE_REPLAY_WINDOW_WORDS);
            }

          /* Set the appropriate bit in the replay window to indicate
             that the corresponding packet has been received. */
          SSH_UINT64_SUB(diff, seq, replay_offset);
          SSH_ASSERT(diff.high == 0);
          bit_ofs = diff.low;

          SSH_ASSERT(bit_ofs < 32 * SSH_ENGINE_REPLAY_WINDOW_WORDS);

          replay_window[bit_ofs / 32] |= ((SshUInt32) 1 << (bit_ofs & 31));

          /* Update anti-replay information in trd. */
          if (rekeyold)
            {
              trd->old_replay_offset_high = replay_offset.high;
              trd->old_replay_offset_low = replay_offset.low;
            }
          else
            {
              trd->replay_offset_high = replay_offset.high;
              trd->replay_offset_low = replay_offset.low;
            }
        }

      FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
      FP_UNLOCK_WRITE(fastpath);
    }

  return TRUE;

 fail:
  FP_RELEASE_TRD(fastpath, pc->transform_index);
  FP_UNLOCK_WRITE(fastpath);
  return FALSE;
}

#ifdef SSHDIST_IPSEC_HWACCEL
/************** Hardware accelerated inbound transform handler **************/

/* Forward declarations of transform handler substeps. */
static void
fastpath_transform_in_finish_hw_combined(SshInterceptorPacket pp,
                                         SshHWAccelResultCode result,
                                         void *context);

static void
fastpath_transform_in_finish_hw_mac(SshInterceptorPacket pp,
                                    SshHWAccelResultCode result,
                                    void *context);

static void
fastpath_transform_in_start_hw_enc(SshFastpath fastpath,
                                   SshEnginePacketContext pc);

static void
fastpath_transform_in_finish_hw_enc(SshInterceptorPacket pp,
                                    SshHWAccelResultCode result,
                                    void *context);

/* Append the higher part of an extended sequence number to packet data
   if the transform specifies ESN. If this returns FALSE the packet has
   been freed. */
static Boolean
fastpath_transform_in_append_seq_high(SshEnginePacketContext pc,
                                      SshUInt16 *mac_len)
{
  unsigned char *ucpw = NULL;

  SSH_ASSERT(pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH));
  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_LONGSEQ);

  /* If using 64 bit sequence numbers, insert the most significant
     32 bits of the sequence number to the packet. This gets included
     in the ICV computation but does not get encrypted. */
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    ucpw = ssh_interceptor_packet_insert(pc->pp, pc->packet_len, 4);
  else if (pc->transform & SSH_PM_IPSEC_ESP)
#endif /* SSH_IPSEC_AH */
    ucpw = ssh_interceptor_packet_insert(pc->pp, pc->u.flow.mac_icv_ofs, 4);

  if (ucpw == NULL)
    return FALSE;

  SSH_PUT_32BIT(ucpw, pc->u.flow.seq_num_high);
  (*mac_len) += 4;
  pc->packet_len += 4;

  return TRUE;
}

/* Delete the previously added higher part of an extended sequence number
   from packet data if the transform specifies ESN. If this returnd FALSE
   the packet has been freed. */
static Boolean
fastpath_transform_in_delete_seq_high(SshFastpathTransformContext tc,
                                      SshEnginePacketContext pc)
{
  size_t longseq_ofs = 0;

  SSH_ASSERT(pc->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH));
  SSH_ASSERT(pc->transform & SSH_PM_IPSEC_LONGSEQ);

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    longseq_ofs = pc->packet_len - 4;
  else if (pc->transform & SSH_PM_IPSEC_ESP)
#endif /* SSH_IPSEC_AH */
    longseq_ofs = pc->packet_len - tc->icv_len - 4;

  if (!ssh_interceptor_packet_delete(pc->pp, longseq_ofs, 4))
    return FALSE;

  pc->packet_len -= 4;

  return TRUE;
}


/* Perform inbound IPsec transform using either hw accelerated combined or
   hw accelerated MAC+decryption transform, or hw accelerated MAC +
   sw decryption or sw MAC + hw accelerated decryption. In case of combined
   transform the transform handler completes without returning to the common
   inbound transform post processing step. Thus L2TP and sw IPcomp are not
   supported when combined hw accelerated transform is used. */
static void
fastpath_transform_in_hw(SshFastpath fastpath,
                         SshFastpathTransformContext tc,
                         SshEnginePacketContext pc)
{
  SshEngineActionRet ret;
  SshFastpathTransformPktOffsetStruct ofs;

  SSH_INTERCEPTOR_STACK_MARK();

  /* This handler is for hw accel only. */
  SSH_ASSERT(tc->transform_accel != NULL
             || tc->encmac_accel != NULL
             || tc->mac_accel != NULL
             || tc->enc_accel != NULL);

  /* Determine the offset of the packet prefix. */
  if (!fastpath_transform_in_calc_pkt_offset(tc, pc, &ofs))
    goto garbage;

  /* Use "combined" transform acceleration, if available. If the hardware
     accelerator can perform antireplay detection, delegate the transform
     to hardware immediately, if not then wait until preliminary antireplay
     detection is done further below before calling the
     ssh_hwaccel_perform_combined function. */
  if (tc->transform_accel
      && !(tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY))
    {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if (tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT
          && pc->ipproto == SSH_IPPROTO_UDP)
        {
          if (!fastpath_transform_remove_natt_header(pc))
            goto error;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing combined transform with AR"));

      pc->u.flow.crypto_state = SSH_FASTPATH_TRANSFORM_IN_ANTIREPLAY_DONE;

      ssh_hwaccel_perform_combined(tc->transform_accel,
                                   pc->pp,
                                   fastpath_transform_in_finish_hw_combined,
                                   (void *)pc);
      return;
    }

  /* Determine the offsets and amounts to decrypt and authenticate, and get
     the sequence number of replay prevention. */
  ret = fastpath_transform_in_parse_hdr(tc, pc, &ofs);
  if (ret == SSH_ENGINE_RET_FAIL)
    goto garbage;
  else if (ret == SSH_ENGINE_RET_ERROR)
    goto error;
  SSH_ASSERT(ret == SSH_ENGINE_RET_OK);

  /* Do preliminary replay prevention screening. */
  if (pc->transform & SSH_PM_IPSEC_ANTIREPLAY)
    {
      if (!fastpath_transform_in_preliminary_antireplay(pc))
        goto antireplay_failure;

      /* Use "combined" transform acceleration, if available. */
      if (tc->transform_accel)
        {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          if (tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT
              && pc->ipproto == SSH_IPPROTO_UDP)
            {
              if (!fastpath_transform_remove_natt_header(pc))
                goto error;
            }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing combined transform"));

          ssh_hwaccel_perform_combined(tc->transform_accel,
                                     pc->pp,
                                     fastpath_transform_in_finish_hw_combined,
                                     (void *)pc);
          return;
        }

    }

  /* Store the packet offsets to pc for post MAC computation use. Here
     we reuse the mac_ofs and mac_len fields, which are not used in
     inbound transform code. */
  pc->u.flow.mac_ofs = ofs.enc_ofs;
  pc->u.flow.mac_len = ofs.enc_len;

  /* Perform message authentication and decryption in hardware. */







  if (tc->encmac_accel)
    {
      /* If using 64 bit sequence numbers, insert the most significant
         32 bits of the sequence number to the packet. This gets included
         in the ICV computation but does not get encrypted. */
      if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          if (!fastpath_transform_in_append_seq_high(pc, &ofs.mac_len))
            goto error;
        }

      /* Use hardware acceleration to compute MAC and to perform decrypt.*/

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Performing hardware MAC and decryption"));
      ssh_hwaccel_perform_ipsec(tc->encmac_accel, pc->pp,
                                ofs.enc_ofs, ofs.enc_len,
                                ofs.mac_ofs, ofs.mac_len,
                                pc->u.flow.mac_icv_ofs,
                                fastpath_transform_in_finish_hw_mac,
                                (void *)pc);
      return;
    }

  /* Perform message authentication in hardware. */
  else if (tc->mac_accel)
    {
      /* If using 64 bit sequence numbers, insert the most significant
         32 bits of the sequence number to the packet. This gets included
         in the ICV computation but does not get encrypted. */
      if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          if (!fastpath_transform_in_append_seq_high(pc, &ofs.mac_len))
            goto error;
        }

      /* Use hardware acceleration to compute the MAC. */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware MAC transform"));
      ssh_hwaccel_perform_ipsec(tc->mac_accel, pc->pp, 0, 0,
                                ofs.mac_ofs, ofs.mac_len,
                                pc->u.flow.mac_icv_ofs,
                                fastpath_transform_in_finish_hw_mac,
                                (void *)pc);
      return;
    }

  /* Perform message authentication in software. */
  else if (tc->with_sw_mac)
    {
      ret = fastpath_transform_in_sw_compute_icv(tc, pc, ofs.mac_ofs,
                                                 ofs.mac_len,
                                                 (SshInt16)(-ofs.natt_len));
      if (ret == SSH_ENGINE_RET_FAIL)
        goto fail;
      else if (ret == SSH_ENGINE_RET_ERROR)
        goto error;
      SSH_ASSERT(ret == SSH_ENGINE_RET_OK);

      fastpath_transform_in_start_hw_enc(fastpath, pc);
      return;
    }

  goto error;

 garbage:
  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_GARBAGE;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  goto fail;

 antireplay_failure:
  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
  goto fail;

 fail:
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_FAIL);
  return;

 error:
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}

/* This is called when "combined" transform hardware acceleration for the
   packet completes. */
static void
fastpath_transform_in_finish_hw_combined(SshInterceptorPacket pp,
                                         SshHWAccelResultCode result,
                                         void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpath fastpath = pc->engine->fastpath;
  unsigned char *ucp;
  SshUInt8 ipproto;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Assign the new packet object to pc. */
  pc->pp = pp;

  /* Check hardware return status. */
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      if (result & SSH_HWACCEL_ICV_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
          pc->audit.corruption = (pc->transform & SSH_PM_IPSEC_AH)
            ? SSH_PACKET_CORRUPTION_AH_ICV_FAILURE
            : SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
        }
      if (result & SSH_HWACCEL_SEQ_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
          if (pc->transform & SSH_PM_IPSEC_AH)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_AH_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
            }
#endif /* SSH_IPSEC_AH */
          if (pc->transform & SSH_PM_IPSEC_ESP)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_ESP_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
            }
          pc->tunnel_id = pc->u.flow.trr->restart_tunnel_id;
        }
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration failed"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp == NULL)
        goto error;

      goto fail;
    }

  /* Perform antireplay detection if not done by the hardware accelerator */
  if ((pc->u.flow.crypto_state & SSH_FASTPATH_TRANSFORM_IN_ANTIREPLAY_DONE)
      == 0)
    {
      if (!fastpath_transform_in_perform_antireplay(pc))
        goto fail;
    }

  /* Update the new packet_len after a combined hwaccel operation */
  pc->packet_len = ssh_interceptor_packet_len(pp);

  /* Update pp->protocol after a combined hwaccel operation. We need
     to get enough information to get both version (first octet) and
     next header (at ofs=6 for ipv6 and ofs=9 - pullup ipv4hlen */
  ucp = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      goto fail;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Original protocol version is %d", pp->protocol));

  if (SSH_IPH_IS6(ucp))
    pp->protocol = SSH_PROTOCOL_IP6;
  else
    pp->protocol = SSH_PROTOCOL_IP4;

  SSH_DEBUG(SSH_D_LOWOK, ("Updated protocol version is %d", pp->protocol));

  if (pp->protocol == SSH_PROTOCOL_IP6)
    ipproto = SSH_IPH6_NH(ucp);
  else
    ipproto = SSH_IPH4_PROTO(ucp);

  /* Dummy ESP packets per rfc4303 section 2.6 are discarded
     here. Note that the same protocol are used both for IPv4 and
     IPv6. */
  if (ipproto == SSH_IPPROTO_IPV6NONXT)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Dummy ESP packet dropped"));
      goto fail;
    }

  /* Return the packet to the transform callback for further processing. */
  ssh_fastpath_release_transform_context(fastpath, pc->u.flow.tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);

  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_DROP);
  return;

 error:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}

static void
fastpath_transform_in_finish_hw_mac(SshInterceptorPacket pp,
                                    SshHWAccelResultCode result,
                                    void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc = pc->u.flow.tc;
  SshFastpath fastpath = pc->engine->fastpath;

  SSH_INTERCEPTOR_STACK_MARK();

  /* This handler is for hw-only macs. */
  SSH_ASSERT(tc->mac_accel != NULL || tc->encmac_accel != NULL);

  /* Assign the new packet object to pc. */
  pc->pp = pp;

  /* Check hardware return status. */
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      if (result & SSH_HWACCEL_ICV_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
          pc->audit.corruption = (pc->transform & SSH_PM_IPSEC_AH)
            ? SSH_PACKET_CORRUPTION_AH_ICV_FAILURE
            : SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
        }
      if (result & SSH_HWACCEL_SEQ_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
          if (pc->transform & SSH_PM_IPSEC_AH)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_AH_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
            }
#endif /* SSH_IPSEC_AH */
          if (pc->transform & SSH_PM_IPSEC_ESP)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_ESP_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
            }
          pc->tunnel_id = pc->u.flow.trr->restart_tunnel_id;
          pc->audit.ip_option = 0;
        }
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp == NULL)
        goto error;

      goto fail;
    }

  /* The hardware accelerator stores the calculated icv in the packet at
     the same place where the original icv was. So we must copy out
     calculated icv and verify it against original icv. */
  if (tc->icv_len > 0)
    {
      unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];

      SSH_ASSERT(tc->icv_len <= sizeof icv);

      ssh_interceptor_packet_copyout(pc->pp, pc->u.flow.mac_icv_ofs, icv,
                                     tc->icv_len);

      /* Just compare the results from hw path and do error handling. */
      if (memcmp(pc->u.flow.packet_icv, icv, tc->icv_len) != 0)
        {
          fastpath_transform_in_icv_error(tc, pc);
          goto fail;
        }
    }

  /* Mark that ICV succesfully verified. */
  pc->pp->flags |= SSH_PACKET_AUTHENTIC;

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
  if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
    {
      if (!fastpath_transform_in_delete_seq_high(tc, pc))
        goto error;
    }

  if (tc->encmac_accel)
    {
      /* Hardware has already computed MAC and done decryption. */
      fastpath_transform_in_finish(fastpath, pc);
    }
  else
    {
      fastpath_transform_in_start_hw_enc(fastpath, pc);
    }

  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_DROP);
  return;

 error:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}

static void
fastpath_transform_in_start_hw_enc(SshFastpath fastpath,
                                   SshEnginePacketContext pc)
{
  SshFastpathTransformContext tc = pc->u.flow.tc;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Decrypt the packet. */
  if (tc->enc_accel)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Performing hardware decryption"));
      ssh_hwaccel_perform_ipsec(tc->enc_accel, pc->pp,
                                pc->u.flow.mac_ofs, /* enc_ofs */
                                pc->u.flow.mac_len, /* enc_len */
                                0, 0, 0,
                                fastpath_transform_in_finish_hw_enc,
                                (void *)pc);
      return;
    }

  if (tc->with_sw_cipher)
    {
      /* Perform the decryption in software. */
      if (ssh_fastpath_esp_transform_in(tc, pc, pc->u.flow.mac_ofs,
                                        pc->u.flow.mac_len) /* enc_len */
          == FALSE)
        {
          goto error;
        }
    }

  /* Continue processing after ICV verification and decryption. */
  fastpath_transform_in_finish(fastpath, pc);
  return;

 error:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}

static void
fastpath_transform_in_finish_hw_enc(SshInterceptorPacket pp,
                                    SshHWAccelResultCode result,
                                    void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpath fastpath = pc->engine->fastpath;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Assign the new packet object to pc. */
  pc->pp = pp;

  /* Check hardware return status. */
  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      if (result & SSH_HWACCEL_ICV_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_MAC_FAIL;
          pc->audit.corruption = (pc->transform & SSH_PM_IPSEC_AH)
            ? SSH_PACKET_CORRUPTION_AH_ICV_FAILURE
            : SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE;
        }
      if (result & SSH_HWACCEL_SEQ_FAILURE)
        {
          pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
#ifdef SSH_IPSEC_AH
          if (pc->transform & SSH_PM_IPSEC_AH)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AHMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_AH_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE;
            }
#endif /* SSH_IPSEC_AH */
          if (pc->transform & SSH_PM_IPSEC_ESP)
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESPMACDROP);
              pc->audit.spi = pc->u.flow.trr->myspis[SSH_PME_SPI_ESP_IN];
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE;
            }
          pc->tunnel_id = pc->u.flow.trr->restart_tunnel_id;
          pc->audit.ip_option = 0;
        }
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp == NULL)
        goto error;

      goto fail;
    }

  /* Continue processing after ICV verification and decryption. */
  fastpath_transform_in_finish(fastpath, pc);
  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_DROP);
  return;

 error:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}
#endif /* SSHDIST_IPSEC_HWACCEL */


/********************** Software inbound transform handler ******************/

static void
fastpath_transform_in_sw(SshFastpath fastpath,
                         SshFastpathTransformContext tc,
                         SshEnginePacketContext pc)
{
  SshEngineActionRet ret;
  SshFastpathTransformPktOffsetStruct ofs;
  Boolean verify_success = FALSE;
  Boolean icv_failure = FALSE;

  SSH_INTERCEPTOR_STACK_MARK();

  /* This handler is for sw-only and for sw-mac+enc_accel. */
  SSH_ASSERT(tc->transform_accel == NULL);
  SSH_ASSERT(tc->encmac_accel == NULL);
  SSH_ASSERT(tc->mac_accel == NULL);
  SSH_ASSERT(tc->enc_accel == NULL);

  /* Determine the offset of the packet prefix. */
  if (!fastpath_transform_in_calc_pkt_offset(tc, pc, &ofs))
    goto garbage;

  /* Determine the offsets and amounts to decrypt and authenticate, and get
     the sequence number of replay prevention. */
  ret = fastpath_transform_in_parse_hdr(tc, pc, &ofs);
  if (ret == SSH_ENGINE_RET_FAIL)
    goto garbage;
  else if (ret == SSH_ENGINE_RET_ERROR)
    goto error;
  SSH_ASSERT(ret == SSH_ENGINE_RET_OK);

  /* Do preliminary replay prevention screening. */
  if (pc->transform & SSH_PM_IPSEC_ANTIREPLAY)
    {
      if (!fastpath_transform_in_preliminary_antireplay(pc))
        goto antireplay_failure;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing software IPsec transform"));

  /* Decrypt and authenticate packet by using combined mode algorithm. */
  if (tc->with_sw_auth_cipher)
    {
      if (pc->transform & SSH_PM_IPSEC_ESP)
        {
          verify_success =
            ssh_fastpath_esp_transform_combined_in(tc, pc, ofs.enc_ofs,
                                                   ofs.enc_len,
                                                   &icv_failure);
          if (verify_success == FALSE)
            {
              if (icv_failure == TRUE)
                {
                  fastpath_transform_in_icv_error(tc, pc);
                  goto fail;
                }

              goto error;
            }
        }

#ifdef SSH_IPSEC_AH
      if (pc->transform & SSH_PM_IPSEC_AH)
        {
          /* GMAC-AES is the only supported auth cipher with AH. */
          SSH_ASSERT(pc->transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC);

          ret =
            fastpath_transform_in_sw_compute_icv(tc, pc, ofs.mac_ofs,
                                                 ofs.mac_len,
                                                 (SshInt16)(-ofs.natt_len));
          if (ret == SSH_ENGINE_RET_FAIL)
            goto fail;
          else if (ret == SSH_ENGINE_RET_ERROR)
            goto error;
          SSH_ASSERT(ret == SSH_ENGINE_RET_OK);
        }
#endif /* SSH_IPSEC_AH */
    }
  else
    {
      /* Perform the MAC computation and verification here in software. */
      if (tc->with_sw_mac)
        {
          ret =
            fastpath_transform_in_sw_compute_icv(tc, pc, ofs.mac_ofs,
                                                 ofs.mac_len,
                                                 (SshInt16)(-ofs.natt_len));
          if (ret == SSH_ENGINE_RET_FAIL)
            goto fail;
          else if (ret == SSH_ENGINE_RET_ERROR)
            goto error;
          SSH_ASSERT(ret == SSH_ENGINE_RET_OK);
        }

      /* Perform the decryption in software. */
      if (tc->with_sw_cipher)
        {
          /* Perform the decryption in software. */
          if (ssh_fastpath_esp_transform_in(tc, pc, ofs.enc_ofs, ofs.enc_len)
              == FALSE)
            {
              goto error;
            }
        }
    }

  /* Continue processing after ICV verification and decryption. */
  fastpath_transform_in_finish(fastpath, pc);
  return;

 garbage:
  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_GARBAGE;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  goto fail;

 antireplay_failure:
  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_REPLAY;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_REPLAYDROP);
  goto fail;

 fail:
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_FAIL);
  return;

 error:
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}


/********************** Inbound transform post crypto ***********************/

/* This is called to complete the packet processing. All crypto operations
   have been performed on a packet when this is called, i.e. the packet has
   been decrypted and authenticity has been verified. This function removes
   IPsec headers and trailers from the packet and performs IPcomp, L2TP and
   transport mode checksum recalculation. */

static void
fastpath_transform_in_finish(SshFastpath fastpath,
                             SshEnginePacketContext pc)
{
  SshFastpathTransformContext tc = pc->u.flow.tc;
  unsigned char prefix[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  unsigned char *ucpw, *seg;
  SshUInt32 trailer_len, prefix_ofs, i;
  size_t prefix_len, esp_ofs = 0;
#ifdef SSH_IPSEC_AH
  size_t ah_ofs = 0;
#endif /* SSH_IPSEC_AH */
  SshUInt16 cks, old_ip_len;
#ifdef SSHDIST_L2TP
  SshUInt16 bits, l2tp_ofs;
#endif /* SSHDIST_L2TP */
  unsigned char trailerhdr[2];
  size_t pad_len, seglen;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  size_t cksum_len;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  SshUInt8 ipproto, old_ipproto;
  SshUInt8 ds_outer, ds_inner, ds_inner_new; /* For ECN processing */
#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  Boolean ipcomp_present = FALSE;
  SshFastpathTransformIpcompStatus ipcomp_status;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  SSH_INTERCEPTOR_STACK_MARK();

  /* The packet has now been authenticated and decrypted.  Copy the prefix
     from the packet into a local buffer so that we don't need to worry about
     interceptor's pullup byte limit.  Note that we don't know the
     exact length of the prefix here (in particular not the length of the
     L2TP header).  Consequently, we copy up to the maximum (if the packet
     has that much data) and determine the length as we parse it. */
  if (tc->prefix_at_0)
    prefix_ofs = 0;
  else
    prefix_ofs = pc->hdrlen;
  prefix_len = pc->packet_len - prefix_ofs;
  if (prefix_len > SSH_ENGINE_MAX_TRANSFORM_PREFIX)
    prefix_len = SSH_ENGINE_MAX_TRANSFORM_PREFIX;

  ssh_interceptor_packet_copyout(pc->pp, prefix_ofs, prefix, prefix_len);

  /* Determine the packet prefix length and offsets to allow decapsulation
     of a packet regardless if it has or does not have UDP encapsulation.
     The offset values in tc are used for outbound transform execution. In
     inbound transform execution the offsets need to be corrected depending
     whether packet and tc NAT-T status match. */

  /* NAT-T packet, non NAT-T tc */
  if (pc->ipproto == SSH_IPPROTO_UDP
      && (pc->transform & SSH_PM_IPSEC_NATT) == 0)
    {
      esp_ofs = tc->esp_ofs + SSH_UDPH_HDRLEN;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs + SSH_UDPH_HDRLEN;
#endif /* SSH_IPSEC_AH */
    }
  else if (pc->ipproto != SSH_IPPROTO_UDP
           && (pc->transform & SSH_PM_IPSEC_NATT))
    {
      /* non NAT-T packet, NAT-T tc */
      esp_ofs = tc->esp_ofs - SSH_UDPH_HDRLEN;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs - SSH_UDPH_HDRLEN;
#endif /* SSH_IPSEC_AH */
    }
  else
    {
      /* Packet matches tc */
      esp_ofs = tc->esp_ofs;
#ifdef SSH_IPSEC_AH
      ah_ofs = tc->ah_ofs;
#endif /* SSH_IPSEC_AH */
    }

  /* Update replay prevention information. */
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      /* This was already checked earlier, so a failure here can only
         be due to a bug. */
      SSH_ASSERT(SSH_AHH_SPI(prefix + ah_ofs) == tc->ah_spi);

      if (!fastpath_transform_in_perform_antireplay(pc))
        goto fail;
    }
  else
#endif /* SSH_IPSEC_AH */
    if (pc->transform & SSH_PM_IPSEC_ESP)
      {
        /* This was already checked earlier, so a failure here can only be
           due to a bug. */
        SSH_ASSERT(SSH_ESPH_SPI(prefix + esp_ofs) == tc->esp_spi);

        if (!fastpath_transform_in_perform_antireplay(pc))
          goto fail;
      }

  /* Delete ESP trailer.  Save next header field from ESP. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      /* Read trailer len into icv [buffer reused for differnet purpose]. */
      ssh_interceptor_packet_copyout(pc->pp, pc->packet_len - tc->trailer_len,
                                     trailerhdr, 2);

      trailer_len = tc->trailer_len + trailerhdr[0];
      ipproto = trailerhdr[1];

      if (pc->packet_len < prefix_ofs + trailer_len)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
          goto garbage;
        }

      /* Verify the ESP self-describing padding */
      pad_len = 0;
      ssh_interceptor_packet_reset_iteration(pc->pp,
                                             pc->packet_len - trailer_len,
                                             trailerhdr[0]);
      while (ssh_interceptor_packet_next_iteration(pc->pp, &seg, &seglen))
        {
          for (i = 0; i < seglen; i++)
            {
              if (seg[i] != pad_len + i + 1)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("Packet has invalid ESP padding"));
                  ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
                  goto garbage;
                }
            }
          pad_len += seglen;
          ssh_interceptor_packet_done_iteration(pc->pp, &seg, &seglen);
        }
      if (seg != NULL || (pad_len != trailerhdr[0]))
        goto fail;

      SSH_DEBUG(SSH_D_LOWOK, ("Total pad length is %d", pad_len));



















      /* Delete the trailer. */
      if (!ssh_interceptor_packet_delete(pc->pp, pc->packet_len - trailer_len,
                                         trailer_len))
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          goto error;
        }
      pc->packet_len -= trailer_len;
    }
  else
    {
      ipproto = SSH_IPPROTO_ANY;
    }

#ifdef SSH_IPSEC_AH
  if ((pc->transform & (SSH_PM_IPSEC_AH | SSH_PM_IPSEC_ESP)) ==
      SSH_PM_IPSEC_AH)
    ipproto = prefix[ah_ofs];
#endif /* SSH_IPSEC_AH */

#ifdef SSHDIST_L2TP
  l2tp_ofs = tc->l2tp_ofs + esp_ofs - tc->esp_ofs;
#endif /* SSHDIST_L2TP */

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  if (pc->transform & SSH_PM_IPSEC_IPCOMP)
    {
      SshUInt32 ipcomp_ofs =
        prefix_ofs + tc->ipcomp_ofs + esp_ofs - tc->esp_ofs;

      /* It is quite possible that even though IPCOMP was negotiated,
         the packet was not compressed */
      if (ipproto == SSH_IPPROTO_IPPCP)
        {
          ipcomp_present = TRUE;
          ipcomp_status =
            ssh_fastpath_transform_ipcomp_inbound(pc, tc, ipcomp_ofs);

          switch (ipcomp_status)
            {
            case SSH_FASTPATH_IPCOMP_SUCCESS:
              SSH_DEBUG(SSH_D_MY, ("Packet is decompressed"));
              break;

            case SSH_FASTPATH_IPCOMP_DROP:
              if (pc->pp == NULL)
                goto error;
              goto garbage;

            case SSH_FASTPATH_IPCOMP_NO_MEMORY:
              if (pc->pp == NULL)
                goto error;
              goto fail;

            default:
              SSH_NOTREACHED;
              if (pc->pp == NULL)
                goto error;
              goto fail;
            }

          /* Parse payload IP protocol. */
          ipproto = prefix[ipcomp_ofs - prefix_ofs];

          /* Copy out the prefix again since l2tp headers might
             have been compressed and they would be seen only now.*/
          prefix_len = pc->packet_len - prefix_ofs;
          if (prefix_len > SSH_ENGINE_MAX_TRANSFORM_PREFIX)
            prefix_len = SSH_ENGINE_MAX_TRANSFORM_PREFIX;

          ssh_interceptor_packet_copyout(pc->pp, prefix_ofs, prefix,
                                         prefix_len);
        }
      else
        {
          SSH_DEBUG(SSH_D_MY, ("Packet was not compressed"));
          ipcomp_present = FALSE;
#ifdef SSHDIST_L2TP
          /* Fix up the L2tp offset that were earlier done thinking that
             IPComp header was included in the prefix. */
          if (pc->transform & SSH_PM_IPSEC_L2TP)
            l2tp_ofs -= 4;
#endif /* SSHDIST_L2TP */
        }
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSHDIST_L2TP
  if (pc->transform & SSH_PM_IPSEC_L2TP)
    {
      unsigned char *hdr;

      /* Get pointer to L2TP UDP header. */
      ucpw = prefix + l2tp_ofs;
      hdr = ucpw;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("L2tp remote port is %u trd %x",
                                   pc->u.flow.trr->l2tp_remote_port,
                                   pc->transform_index));

      /* Sanity check the L2TP UDP header. */
      if ((pc->u.flow.trr->l2tp_remote_port
           && SSH_UDPH_SRCPORT(ucpw) != pc->u.flow.trr->l2tp_remote_port)
          || (pc->u.flow.trr->l2tp_local_port
              && SSH_UDPH_DSTPORT(ucpw) != pc->u.flow.trr->l2tp_local_port))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("L2TP port mismatch: src=%d(%d), dst=%d(%d)",
                     (int) SSH_UDPH_SRCPORT(ucpw),
                     (int) pc->u.flow.trr->l2tp_remote_port,
                     (int) SSH_UDPH_DSTPORT(ucpw),
                     (int) pc->u.flow.trr->l2tp_local_port));
          goto garbage;
        }

      if (pc->u.flow.trr->l2tp_remote_port == 0)
        {
          SshEngineTransformData trd;

          FP_LOCK_WRITE(fastpath);
          trd = FP_GET_TRD(fastpath, pc->transform_index);
          if (trd == NULL)
            {
              FP_RELEASE_TRD(fastpath, pc->transform_index);
              FP_UNLOCK_WRITE(fastpath);
              goto garbage;
            }
          trd->l2tp_remote_port = SSH_UDPH_SRCPORT(ucpw);
          FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
          FP_UNLOCK_WRITE(fastpath);

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Updated L2tp remote port to %u",
                                       SSH_UDPH_SRCPORT(ucpw)));

          pc->u.flow.trr->l2tp_remote_port = SSH_UDPH_SRCPORT(ucpw);
        }

      ucpw += SSH_UDP_HEADER_LEN;

      /* Sanity check the L2TP header. */
      if (SSH_L2TPH_VERSION(ucpw) != SSH_L2TP_DATA_MESSAGE_HEADER_VERSION)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP header version mismatch"));
          goto garbage;
        }
      bits = SSH_L2TPH_BITS(ucpw);
      ucpw += 2;

      /* Check for L2TP control messages.  They are passed to the
         local stack with tunnel id 1. */
      if (bits & SSH_L2TPH_F_TYPE)
        {
          size_t len;

          /* Assign SSH private AVP which tells the transform index of
             the SA protecting the L2TP traffic.  The private AVP is
             added only for non-empty control messages. */
          if ((bits & SSH_L2TPH_F_LENGTH) == 0
              || SSH_GET_16BIT(ucpw) <= 12)
            /* A message without the length field or an empty
               message. */
            goto l2tp_pass_to_local_stack;

          /* Update length field in the UDP header. */

          len = SSH_UDPH_LEN(hdr);
          SSH_UDPH_SET_LEN(hdr, len + 10);

          /* Clear UDP checksum. */
          SSH_UDPH_SET_CHECKSUM(hdr, 0);

          /* Update L2TP header length. */
          SSH_ASSERT(bits & SSH_L2TPH_F_LENGTH);
          len = SSH_GET_16BIT(ucpw);
          SSH_PUT_16BIT(ucpw, len + 10);

          /* Insert update UDP + L2TP header back to the packet. */
          if (!ssh_interceptor_packet_copyin(pc->pp,
                                             prefix_ofs + l2tp_ofs,
                                             hdr, ucpw - hdr + 2))
            {
              SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
              goto error;
            }

          /* Insert AVP to the end of the packet. */
          ucpw = ssh_interceptor_packet_insert(pc->pp, pc->packet_len, 10);
          if (ucpw == NULL)
            goto error;

          /* The packet did grow. */
          pc->packet_len += 10;

          memset(ucpw, 0, 10);
          SSH_L2TP_AVP_SET_LENGTH(ucpw, 10);
          SSH_L2TP_AVP_SET_VENDOR_ID(ucpw, SSH_PRIVATE_ENTERPRISE_CODE);
          SSH_L2TP_AVP_SET_ATTRIBUTE_TYPE(ucpw,
                                          SSH_L2TP_SSH_AVP_TRANSFORM_INDEX);
          SSH_PUT_32BIT(ucpw + 6, pc->transform_index);

          goto l2tp_pass_to_local_stack;
        }

      if (bits & SSH_L2TPH_F_LENGTH)
        ucpw += 2; /* Skip length; IP sanity check after restart will remove
                      any trailing garbage. */

      /* Check tunnel and session IDs if they are set for the
         transform run. */
      if ((pc->u.flow.trr->l2tp_local_tunnel_id
           && SSH_GET_16BIT(ucpw) != pc->u.flow.trr->l2tp_local_tunnel_id)
          || (pc->u.flow.trr->l2tp_local_session_id
              && SSH_GET_16BIT(ucpw + 2)
              != pc->u.flow.trr->l2tp_local_session_id))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP tunnel/session ID mismatch"));
          goto garbage;
        }
      ucpw += 4; /* skip tunnel id, session id */

      if (bits & SSH_L2TPH_F_SEQUENCE)
        {
          SshEngineTransformData trd;

          FP_LOCK_WRITE(fastpath);
          trd = FP_GET_TRD(fastpath, pc->transform_index);
          if (trd)
            trd->l2tp_seq_nr = SSH_GET_16BIT(ucpw + 2);
          FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
          FP_UNLOCK_WRITE(fastpath);
          ucpw += 4;
        }
      if (bits & SSH_L2TPH_F_OFFSET)
        {
          ucpw += 2;
        }

      /* Parse PPP header. */
      if (ucpw[0] == 0xff) /* First byte of ppp header */
        {
          /* We must have the address control field. */
          if (ucpw[1] != 0x03)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("L2TP PPP address control fail"));
              goto garbage;
            }
          ucpw += 2;
        }

      /* Skip zero padding, check we still may have payload. */
      while (ucpw < (prefix + SSH_ENGINE_MAX_TRANSFORM_PREFIX) && ucpw[0] == 0)
        ucpw++;
      if (ucpw == (prefix + SSH_ENGINE_MAX_TRANSFORM_PREFIX))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("L2TP PPP padding too long"));
          goto garbage;
        }

      if (ucpw[0] != SSH_PPP_PROTO_IP && ucpw[0] != SSH_PPP_PROTO_IPV6)
        {
        l2tp_pass_to_local_stack:
          /* Cause the L2TP UDP header to be left in the packet, cause the
             outer IP header to be left in the packet, and cause the
             packet to be restarted with tunnel id 1. */
          prefix_ofs = pc->hdrlen;
          prefix_len = l2tp_ofs - tc->iphdrlen;
          pc->u.flow.trr->restart_tunnel_id = 1;
          ipproto = SSH_IPPROTO_UDP;
        }
      else
        {
          if (ucpw[0] == SSH_PPP_PROTO_IP)
            ipproto = SSH_IPPROTO_IPIP;
          else
            ipproto = SSH_IPPROTO_IPV6;
          prefix_len = (ucpw - prefix) + 1;
#ifdef SSHDIST_IPSEC_NAT
          /* In the case of L2TP the internal nat is to be performed
             only for the non-decapsulated control traffic, not the
             PPP decapsulated IPv4/IPv6 traffic. */
          SSH_IP_UNDEFINE(&pc->u.flow.internal_nat_ip);
#endif /* SSHDIST_IPSEC_NAT */
        }
    }
  else
#endif /* SSHDIST_L2TP */
    {
      /* Calculate correct prefix_len. Note that the length in 'tc' is for
         outbound transform execution and it might need to be updated
         depending on packet NAT-T status. See comments above, where
         offsets are calculated similarly. */

      if (pc->ipproto == SSH_IPPROTO_UDP
          && (pc->transform & SSH_PM_IPSEC_NATT) == 0)
        prefix_len = tc->prefix_len + SSH_UDPH_HDRLEN;
      else if (pc->ipproto != SSH_IPPROTO_UDP
               && (pc->transform & SSH_PM_IPSEC_NATT))
        prefix_len = tc->prefix_len - SSH_UDPH_HDRLEN;
      else
        prefix_len = tc->prefix_len;

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
      /* Account for prefix length if no IPComp header is present */
      if ((pc->transform & SSH_PM_IPSEC_IPCOMP) && !ipcomp_present)
        prefix_len -= 4;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */
    }

  /* Sanity check if packet is too short; perhaps headers were
     corrupt. */
  if (prefix_ofs + prefix_len >= pc->packet_len)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short"));
      goto garbage;
    }

  /* Eliminate the prefix from the packet.  After this block, ipproto
     must be the next protocol */

  /* Tunnel mode */
  if (prefix_ofs == 0)
    {
      /* Delete tunnel mode prefix. */
      if (!ssh_interceptor_packet_delete(pc->pp, 0, prefix_len))
        goto error;
      pc->packet_len -= prefix_len;

      /* ECN processing (1) grab information. If the inner header
         specifies ECT(0) = 10 or ECT(1) = 01 and the outer header is
         set to CE then set inner header DS value to CE (11) */
      if (pc->pp->protocol == SSH_PROTOCOL_IP4)
        ds_outer = SSH_IPH4_TOS(prefix);
      else
        ds_outer = SSH_IPH6_CLASS(prefix);

      /* Set pc->pp->protocol based on ipproto. */
      if (ipproto == SSH_IPPROTO_IPIP)
        {
          if (pc->packet_len < SSH_IPH4_HDRLEN)
            goto garbage;

          pc->pp->protocol = SSH_PROTOCOL_IP4;
        }
      else
        {
          if (ipproto == SSH_IPPROTO_IPV6)
            {
              if (pc->packet_len < SSH_IPH6_HDRLEN)
                goto garbage;

              pc->pp->protocol = SSH_PROTOCOL_IP6;
            }
          else
            {
              unsigned char ip_version;

              SSH_DEBUG(SSH_D_FAIL, ("unexpected tunnel ipproto %d",
                                     ipproto));

              if (pc->packet_len < SSH_IPH4_HDRLEN)
                goto garbage;

              /* It might make sense to drop the packet here as
                 invalid.  However, following the general "strict on
                 reception, permissive on reception" rule we allow
                 the packet through. Set pc->pp->protocol to the
                 address type of the decapsulated packet. */
              ssh_interceptor_packet_copyout(pc->pp, 0, &ip_version, 1);
              if (SSH_IPH_IS4(&ip_version))
                pc->pp->protocol = SSH_PROTOCOL_IP4;
              else if (SSH_IPH_IS6(&ip_version) &&
                       pc->packet_len >= SSH_IPH6_HDRLEN)
                pc->pp->protocol = SSH_PROTOCOL_IP6;
              else
                goto garbage;
            }
        }

      /* Focus into inner protocol */
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN);
          if (ucpw == NULL)
            goto error;
          ipproto = SSH_IPH6_NH(ucpw);
        }
      else
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH4_HDRLEN);
          if (ucpw == NULL)
            goto error;
          ipproto = SSH_IPH4_PROTO(ucpw);
        }

      /* ECN processing (2); update value */
      if (pc->pp->protocol == SSH_PROTOCOL_IP4)
        ds_inner = SSH_IPH4_TOS(ucpw);
      else
        ds_inner = SSH_IPH6_CLASS(ucpw);

      /* If congestion experienced and can handle that */
      if (((ds_outer & 0x3) == 0x3)
          && ((ds_inner & 0x3) == 0x1 || (ds_inner & 0x3) == 0x2))
        {
          ds_inner_new = ds_inner | 0x3;

          if (pc->pp->protocol == SSH_PROTOCOL_IP4)
            {
              SSH_IPH4_SET_TOS(ucpw, ds_inner_new);

              cks = SSH_IPH4_CHECKSUM(ucpw);
              cks = ssh_ip_cksum_update_byte(cks,
                                             SSH_IPH4_OFS_TOS,
                                             ds_inner, ds_inner_new);
              SSH_IPH4_SET_CHECKSUM(ucpw, cks);
            }
          else
            {
              SSH_IPH6_SET_CLASS(ucpw, ds_inner_new);
            }
        }

      /* Clear fragmentation allowed flag from pp */
      pc->pp->flags &= ~SSH_PACKET_FRAGMENTATION_ALLOWED;
    }

  /* Transport mode */
  else
    {
      /* Delete IPsec headers. */
      if (!ssh_interceptor_packet_delete(pc->pp, prefix_ofs, prefix_len))
        goto error;
      pc->packet_len -= prefix_len;

      /* Update ipproto and length from the original ip header. */
      if (pc->packet_len < tc->iphdrlen)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Packet too short to contain IP hdr"));
          goto garbage;
        }
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          SSH_ASSERT(pc->ipsec_offset_prevnh > 0
                     && pc->ipsec_offset_prevnh < prefix_ofs);

          /* Update packet length and next header. */
          ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN);
          if (!ucpw)
            goto error;

          SSH_IPH6_SET_LEN(ucpw, pc->packet_len - SSH_IPH6_HDRLEN);

          /* A slight optimization which avoids a useless call to
             `ssh_interceptor_packet_copyin'. */
          if (pc->ipsec_offset_prevnh < SSH_IPH6_HDRLEN)
            {
              SSH_IPH6_SET_NH(ucpw, ipproto);
            }
          else
            {
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 pc->ipsec_offset_prevnh,
                                                 &ipproto, 1))
                goto error;
            }
        }
      else
#endif /* WITH_IPV6 */
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, tc->iphdrlen);
          if (!ucpw)
            goto error;

          cks = SSH_IPH4_CHECKSUM(ucpw);
          old_ipproto = SSH_IPH4_PROTO(ucpw);
          old_ip_len = SSH_IPH4_LEN(ucpw);
          SSH_IPH4_SET_LEN(ucpw, pc->packet_len);
          SSH_IPH4_SET_PROTO(ucpw, ipproto);

          cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_PROTO, old_ipproto,
                                         ipproto);
          cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_LEN, old_ip_len,
                                          (SshUInt16) pc->packet_len);

          SSH_IPH4_SET_CHECKSUM(ucpw, cks);
        }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Update possible TCP/UDP/ICMPv6 checksum in case

         1) a NAT has been detected between the peers, or
         2) TCP encapsulation is enabled for the transform (in this case we
            cannot not detect if there was a NAT between the peers)
      */
      if (((pc->u.flow.trr->natt_flags & (SSH_ENGINE_NATT_REMOTE_BEHIND_NAT
                                          | SSH_ENGINE_NATT_LOCAL_BEHIND_NAT))
#ifdef SSH_IPSEC_TCPENCAP
           || pc->u.flow.trr->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX
#endif /* SSH_IPSEC_TCPENCAP */
           )
          && (
#if defined (WITH_IPV6)
              ipproto == SSH_IPPROTO_IPV6ICMP ||
#endif /* WITH_IPV6 */
              ipproto == SSH_IPPROTO_TCP ||
              ipproto == SSH_IPPROTO_UDP ||
              ipproto == SSH_IPPROTO_UDPLITE))
        {
          size_t cksum_ofs = 0, header_len = 0;
          unsigned char cksum_buf[2];

          /* Fetch offsets of the protocol header. */
          if (ipproto == SSH_IPPROTO_UDP || ipproto == SSH_IPPROTO_UDPLITE)
            {
              cksum_ofs = SSH_UDPH_OFS_CHECKSUM;
              header_len = SSH_UDPH_HDRLEN;
            }
          else if (ipproto == SSH_IPPROTO_TCP)
            {
              cksum_ofs = SSH_TCPH_OFS_CHECKSUM;
              header_len = SSH_TCPH_HDRLEN;
            }
#if defined (WITH_IPV6)
          else
            {
              cksum_ofs = SSH_ICMP6H_OFS_CHECKSUM;
              header_len = SSH_ICMP6H_HDRLEN;
            }
#endif /* WITH_IPV6 */

          /* Sanity check packet length. */
          if (pc->packet_len < tc->iphdrlen + header_len)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Packet too short to contain TCP/UDP header"));
              goto garbage;
            }

          /* Get the original checksum. */
          ssh_interceptor_packet_copyout(pc->pp,
                                         tc->iphdrlen + cksum_ofs,
                                         cksum_buf, 2);
          cks = SSH_GET_16BIT(cksum_buf);

          /* Special checks for UDP. */
          if (ipproto == SSH_IPPROTO_UDP)
            {
              /* The original checksum is zero. No need to update. */
              if (cks == 0)
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Not updating zero UDP checksum"));
                  goto natt_local_end_compensated;
                }

              /* The packet is authenticated. Simply clear the UDP checksum. */
              if (pc->pp->flags & SSH_PACKET_AUTHENTIC)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Clearing checksum of ESP authenticated "
                             "UDP packet"));
                  memset(cksum_buf, 0, 2);
                  if (!ssh_interceptor_packet_copyin(pc->pp,
                                                     tc->iphdrlen
                                                     + cksum_ofs,
                                                     cksum_buf, 2))
                    goto error;

                  goto natt_local_end_compensated;
                }
            }

          /* Check if checksum can be updated incrementally. */
          if (pc->u.flow.trr->natt_flags
              & (SSH_ENGINE_NATT_OA_L | SSH_ENGINE_NATT_OA_R))
            {
              unsigned char current_ip[SSH_IP_ADDR_SIZE];
              int addrlen;

              SSH_DEBUG(SSH_D_LOWOK,
                        ("Performing incremental checksum updating"));

              /* Update source IP if remote NAT-OA is set. */
              if (pc->u.flow.trr->natt_flags & SSH_ENGINE_NATT_OA_R)
                {
                  /* Store the packet's current source IP address. */
                  SSH_IP_ENCODE(&pc->src, current_ip, addrlen);

                  for (i = 0; i < addrlen; i += 4)
                    cks =
                      ssh_ip_cksum_update_long(cks, i,
                                               SSH_GET_32BIT(pc->u.flow.
                                                             trr->natt_oa_r
                                                             + i),
                                               SSH_GET_32BIT(current_ip + i));
                }

              /* Update destination IP if local NAT-OA is set. */
              if (pc->u.flow.trr->natt_flags & SSH_ENGINE_NATT_OA_L)
                {
                  /* Store the packet's current destination IP
                     address. */
                  SSH_IP_ENCODE(&pc->dst, current_ip, addrlen);

                  for (i = 0; i < addrlen; i += 4)
                    cks =
                      ssh_ip_cksum_update_long(cks, i,
                                               SSH_GET_32BIT(pc->u.flow.
                                                             trr->natt_oa_l
                                                             + i),
                                               SSH_GET_32BIT(current_ip + i));
                }

              /* Copy checksum back to the packet. */
              SSH_PUT_16BIT(cksum_buf, cks);
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2))
                goto error;
            }

          /* Update the checksum by computing it over the whole packet. */
          else
            {

              /* SSH_IP6_PSEUDOH_HDRLEN is long enough to hold also
                 TCP protocol header. */
              unsigned char pseudohdr[SSH_IP6_PSEUDOH_HDRLEN];
              size_t pseudohdrlen, len;
              SshUInt32 sum;

              /* Special checks for UDP-Lite. */
              if (ipproto == SSH_IPPROTO_UDPLITE)
                {
                  ucpw = ssh_interceptor_packet_pullup(pc->pp,
                                                       tc->iphdrlen
                                                       + SSH_UDPH_HDRLEN);
                  if (ucpw == NULL)
                    goto error;
                  ucpw += tc->iphdrlen;

                  cksum_len = SSH_UDP_LITEH_CKSUM_COVERAGE(ucpw);
                  if (cksum_len > pc->packet_len - tc->iphdrlen)
                    goto error;
                }
              else
                {
                  cksum_len = pc->packet_len - tc->iphdrlen;
                }

              SSH_DEBUG(SSH_D_LOWSTART, ("Updating protocol checksum"));

              /* The length field in the pseudo header. */
              len = pc->packet_len - tc->iphdrlen;

              /* Construct pseudo header. */
              memset(pseudohdr, 0, sizeof(pseudohdr));
#if defined (WITH_IPV6)
              if (pc->pp->protocol == SSH_PROTOCOL_IP6)
                {
                  ucpw = ssh_interceptor_packet_pullup(pc->pp,
                                                       SSH_IPH6_HDRLEN);
                  if (ucpw == NULL)
                    goto error;

                  pseudohdrlen = SSH_IP6_PSEUDOH_HDRLEN;

                  memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_SRC,
                         ucpw + SSH_IPH6_OFS_SRC, SSH_IPH6_ADDRLEN);
                  memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_DST,
                         ucpw + SSH_IPH6_OFS_DST, SSH_IPH6_ADDRLEN);
                  SSH_IP6_PSEUDOH_SET_LEN(pseudohdr, len);
                  SSH_IP6_PSEUDOH_SET_NH(pseudohdr, ipproto);
                }
              else
#endif /* WITH_IPV6 */
                {
                  ucpw = ssh_interceptor_packet_pullup(pc->pp, tc->iphdrlen);
                  if (ucpw == NULL)
                    goto error;

                  pseudohdrlen = SSH_TCPH_PSEUDO_HDRLEN;

                  memcpy(pseudohdr + SSH_TCPH_PSEUDO_OFS_SRC,
                         ucpw + SSH_IPH4_OFS_SRC, SSH_IPH4_ADDRLEN);
                  memcpy(pseudohdr + SSH_TCPH_PSEUDO_OFS_DST,
                         ucpw + SSH_IPH4_OFS_DST, SSH_IPH4_ADDRLEN);
                  SSH_PUT_8BIT(pseudohdr + SSH_TCPH_PSEUDO_OFS_PTCL, ipproto);
                  SSH_PUT_16BIT(pseudohdr + SSH_TCPH_PSEUDO_OFS_TCPLEN, len);
                }

              /* Clear checksum from the protocol header. */
              memset(cksum_buf, 0, 2);
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2))
                goto error;

              /* Compute checksum. */
              sum = 0;
              cks = ~ssh_ip_cksum(pseudohdr, pseudohdrlen);
              sum += cks;
              cks = ~ssh_ip_cksum_packet(pc->pp, tc->iphdrlen, cksum_len);
              sum += cks;

              /* Fold 32 bit checksum to 16 bits. */
              sum = (sum & 0xffff) + (sum >> 16);
              sum = (sum & 0xffff) + (sum >> 16);
              cks = (SshUInt16)~sum;

              /* Store the computed checksum. */
              SSH_PUT_16BIT(cksum_buf, cks);
              if (!ssh_interceptor_packet_copyin(pc->pp,
                                                 tc->iphdrlen + cksum_ofs,
                                                 cksum_buf, 2))
                goto error;
            }
        natt_local_end_compensated:
          ;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Allow fragmentation after transport mode IPsec decapsulation.
         This is necessary as the IPsec packet may have been reassembled
         before IPsec decapsulation and therefore the plaintext packet
         size may exceed interface mtu. */
      pc->pp->flags |= SSH_PACKET_FRAGMENTATION_ALLOWED;
    }

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  /* Dummy ESP packets per rfc4303 section 2.6 are discarded
     here. Note that the same protocol are used both for IPv4 and
     IPv6. */
  if (ipproto == SSH_IPPROTO_IPV6NONXT)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Dummy ESP packet dropped"));
      goto fail;
    }

  /* If the packet TCP/UDP checksum has already been verified by
     hardware, then we clear the flag to indicate that protocol stack
     should re-verify the checksum. */
  if (pc->pp->flags & SSH_PACKET_HWCKSUM)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Clearing HW cksum flag from decapsulated packet"));
      pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
    }

  SSH_DUMP_PACKET(SSH_D_PCKDMP, "Plaintext:", pc->pp);

  /* Return the packet to the transform callback for further processing. */
  ssh_fastpath_release_transform_context(fastpath, pc->u.flow.tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);
  return;

 garbage:
  SSH_DEBUG(SSH_D_NETGARB, ("Corrupt packet received"));
  SSH_DUMP_PACKET(SSH_D_PCKDMP, "packet when corrupt:", pc->pp);
  SSH_DEBUG_HEXDUMP(SSH_D_NETGARB, ("prefix:"), prefix, sizeof(prefix));

  pc->u.flow.trr->statflags |= SSH_ENGINE_STAT_T_GARBAGE;
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_FAIL);
  return;

 fail:
  SSH_DEBUG(SSH_D_NETGARB, ("inbound transform failed"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_DROP);
  return;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("inbound transform error"));
  fastpath_transform_in_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
}
