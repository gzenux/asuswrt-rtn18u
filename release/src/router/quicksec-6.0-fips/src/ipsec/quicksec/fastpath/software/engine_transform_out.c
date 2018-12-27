/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to implement IPsec and other transforms for outgoing packets.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSHDIST_L2TP
#include "sshl2tp_parse.h"
#endif /* SSHDIST_L2TP */

#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformOut"


/******************** Outbound transform building blocks ********************/

/* The various transforms (headers) are always in the following order:
   IP [NATT] [AH] [ESP] [IPCOMP] [UDP+L2TP] [IPIP]
   Each individual header has fixed size:
   [IP 20 bytes, 40 for IPv6]
   NATT 16 bytes
   AH 12+MAClen bytes
   ESP 8 bytes + trailer 2+MAClen to 255+2+MAClen bytes
   IPCOMP 4 bytes - variable compression gain
   UDP+L2TP 37-44 bytes depending on options
*/

/* Utility function to calculate NATT udp hdr checksum. */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
static Boolean
fastpath_transform_calc_natt_udp_header_checksum(
                                             SshFastpathTransformContext tc,
                                             SshEnginePacketContext pc)
{
  unsigned char pseudohdr[SSH_IP6_PSEUDOH_HDRLEN];
  unsigned char tmp_buf[2];
  unsigned char *ucpw;
  SshUInt16 checksum;
  SshUInt16 udp_offset;
  SshUInt32 sum;
  int udp_len = 0;

  if (pc->pp->protocol == SSH_PROTOCOL_IP4)
    {
      /* Don't calculate checksum for IPv4 packets. */
      return TRUE;
    }
#if defined (WITH_IPV6)
  else if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      ucpw = ssh_interceptor_packet_pullup(pc->pp, SSH_IPH6_HDRLEN);
      if (ucpw == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Pullup failed"));
          pc->pp = NULL;

          return FALSE;
        }

      /* Determine where UDP header starts. */
      if (tc->prefix_at_0)
        udp_offset = tc->natt_ofs;
      else
        udp_offset = tc->natt_ofs + pc->ipsec_offset;

      /* Get UDP packet length */
      ssh_interceptor_packet_copyout(pc->pp,
                                     udp_offset + SSH_UDPH_OFS_LEN,
                                     tmp_buf, 2);
      udp_len = SSH_GET_16BIT(tmp_buf);

      /* Constrcut pseudo header */
      memset(pseudohdr, 0, sizeof(pseudohdr));
      memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_SRC,
             ucpw + SSH_IPH6_OFS_SRC, SSH_IPH6_ADDRLEN);
      memcpy(pseudohdr + SSH_IP6_PSEUDOH_OFS_DST,
             ucpw + SSH_IPH6_OFS_DST, SSH_IPH6_ADDRLEN);
      SSH_IP6_PSEUDOH_SET_LEN(pseudohdr, udp_len);
      SSH_IP6_PSEUDOH_SET_NH(pseudohdr, SSH_IPPROTO_UDP);

      /* Calculate UDP checksum */
      sum = 0;
      checksum = ~ssh_ip_cksum(pseudohdr, SSH_IP6_PSEUDOH_HDRLEN);
      sum += checksum;
      checksum = ~ssh_ip_cksum_packet(pc->pp, udp_offset, udp_len);
      sum += checksum;

      /* Fold 32 bit checksum to 16 bits. */
      sum = (sum & 0xffff) + (sum >> 16);
      sum = (sum & 0xffff) + (sum >> 16);
      checksum = (SshUInt16)~sum;

      /* Store the computed checksum. */
      SSH_PUT_16BIT(tmp_buf, checksum);
      if (!ssh_interceptor_packet_copyin(pc->pp,
                                         udp_offset + SSH_UDPH_OFS_CHECKSUM,
                                         tmp_buf, 2))
        {
          SSH_DEBUG(SSH_D_FAIL, ("copyin failed, dropping packet"));
          pc->pp = NULL;

          return FALSE;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("UDP checksum calculation: checksum=%x, offset=%d",
                 checksum, udp_offset + SSH_UDPH_OFS_CHECKSUM));

      return TRUE;
    }
#endif /* (WITH_IPV6) */
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Trying to calculate NAT-T checksum to non IP packet"));
      return FALSE;
    }
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSHDIST_IPSEC_HWACCEL
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
static Boolean
fastpath_transform_add_natt_header(SshFastpathTransformContext tc,
                                   SshEnginePacketContext pc)
{
  unsigned char prefix[SSH_UDPH_HDRLEN];
  unsigned char *ucp;
  SshUInt16 cks, old_len, prefix_ofs, header_len;
  SshUInt8 proto;

  /* Only ESP is supported by the latest drafts and RFC. */
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    return TRUE;
#endif /* SSH_IPSEC_AH */

  /* Pull up the header by IP version and sanity check on it. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP4)
    {
      header_len = SSH_IPH4_HDRLEN;
    }
#if defined (WITH_IPV6)
  else if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      header_len = SSH_IPH6_HDRLEN;
    }
#endif /* (WITH_IPV6) */
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Trying to add NAT-T to non IP packet"));
      return TRUE;
    }

  /* Pullup IP header. */
  ucp = ssh_interceptor_packet_pullup(pc->pp, header_len);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Pullup of IP header failed failed"));
      goto error;
    }

  if (tc->prefix_at_0)
    {
      prefix_ofs = 0;
    }
  else
    {
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        prefix_ofs = pc->ipsec_offset;
      else
#endif /* WITH_IPV6 */
        prefix_ofs = pc->hdrlen;
    }

  /* Update the new packet_len after insertion
     of NAT-T header operation,size of the NATT
     header is 8 bytes */
  old_len = (SshUInt16) pc->packet_len;
  pc->packet_len += SSH_UDPH_HDRLEN;

  /* Build NAT-T UDP header. */
  SSH_UDPH_SET_SRCPORT(prefix, pc->u.flow.trr->local_port);
  SSH_UDPH_SET_DSTPORT(prefix, pc->u.flow.trr->remote_port);
  SSH_UDPH_SET_LEN(prefix, pc->packet_len - tc->natt_ofs - prefix_ofs);
  SSH_UDPH_SET_CHECKSUM(prefix, 0);

  /* Update the next protocol (ip_nh) field and
     checksum in the IP header.In the case of IPv4
     there is checksum field otherwise there is no
     such field for the IPv6 */

#if defined (WITH_IPV6)
  if (SSH_IP_IS6(&pc->u.flow.trr->gw_addr))
    {
      /* Update IPv6 header. */
      SSH_IPH6_SET_LEN(ucp, pc->packet_len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_NH(ucp, tc->ip_nh);
    }
  else
#endif /* WITH_IPV6 */
    {
      cks = SSH_IPH4_CHECKSUM(ucp);

      proto = SSH_IPH4_PROTO(ucp);
      SSH_IPH4_SET_PROTO(ucp, tc->ip_nh);
      cks = ssh_ip_cksum_update_byte(cks,
                                     SSH_IPH4_OFS_PROTO,
                                     proto, tc->ip_nh);
      SSH_IPH4_SET_LEN(ucp, pc->packet_len);
      cks = ssh_ip_cksum_update_short(cks,
                                      SSH_IPH4_OFS_LEN,
                                      old_len, (SshUInt16) pc->packet_len);
      SSH_IPH4_SET_CHECKSUM(ucp, cks);
    }

  /* Insert the UDP header into the packet. */
  ucp = ssh_interceptor_packet_insert(pc->pp, header_len, SSH_UDPH_HDRLEN);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("insert failed"));
      goto error;
    }
  memcpy(ucp, prefix, SSH_UDPH_HDRLEN);

  return TRUE;

 error:
  pc->pp = NULL;
  return FALSE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_HWACCEL */

static Boolean
fastpath_transform_process_df(SshEnginePacketContext pc)
{
  SshUInt16 cks, fragoff;
  unsigned char *ucpw;

  ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
  if (ucpw == NULL)
    {
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
      return FALSE;
    }

  /* Get the fragoff from pullup packet */
  fragoff = SSH_IPH4_FRAGOFF(ucpw);

  /* Do relevant changes for the df_bit_flag */
  if (((fragoff & SSH_IPH4_FRAGOFF_DF)
       && pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
      || (!(fragoff & SSH_IPH4_FRAGOFF_DF)
          && pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_SET))
    {
      SshUInt16 newfragoff;

      /* Get the old checksum value */
      cks = SSH_IPH4_CHECKSUM(ucpw);
      if (pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_CLEAR)
        newfragoff =  fragoff & ~SSH_IPH4_FRAGOFF_DF;
      else
        newfragoff =  fragoff | SSH_IPH4_FRAGOFF_DF;

      SSH_IPH4_SET_FRAGOFF(ucpw, newfragoff);
      cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_FRAGOFF,
                                      fragoff, newfragoff);
      /* Set the new updated cks into ucpw */
      SSH_IPH4_SET_CHECKSUM(ucpw, cks);

      /* Update pc */
      pc->fragment_offset = newfragoff;
    }

  return TRUE;
}

/* Send ICMP fragneeded/toobig. Returns TRUE if this was done. In that
   case the caller shall indicate failure for the packet. */
static Boolean
fastpath_transform_process_pmtu(SshFastpath fastpath,
                                SshEnginePacketContext pc,
                                SshFastpathTransformContext tc,
                                SshPmTransform transform)
{
  SshUInt16 min_mtu_value, mtu_value;

  /* Calculate minimum allowed MTU based on the family */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    min_mtu_value = (SshUInt16)SSH_ENGINE_MIN_FIRST_FRAGMENT_V6;
  else
#endif /* WITH_IPV6 */
    min_mtu_value = (SshUInt16)SSH_ENGINE_MIN_DF_LENGTH;

  /* Calculate MTU value to send. This is the one at flow (which,
     again is either the one from interface towards next hop, or the
     one received from route with ICMP to this transform) compensated
     with our own discount. */
  mtu_value = pc->u.flow.mtu - pc->u.flow.tr.packet_enlargement;

  /* Check if to send ICMP. We do this for the first really offending
     packet if the MTU is above protocol defined minimum value (stacks
     tend to drop ICMP's with too small MTU proposals) */
  if (mtu_value >= min_mtu_value)
    {
      if (pc->pp->protocol == SSH_PROTOCOL_IP4)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Sending ICMP too big for IPv4: dst %@  MTU %d",
                     ssh_ipaddr_render, &pc->dst,
                     mtu_value));

          ssh_engine_send_icmp_error(fastpath->engine, pc,
                                     SSH_ICMP_TYPE_UNREACH,
                                     SSH_ICMP_CODE_UNREACH_NEEDFRAG,
                                     mtu_value);

          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
          return TRUE;
        }
#if defined (WITH_IPV6)
      else if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Sending ICMP too big for IPv6: dst %@  MTU %d",
                     ssh_ipaddr_render, &pc->dst,
                     mtu_value));

          ssh_engine_send_icmp_error(fastpath->engine, pc,
                                     SSH_ICMP6_TYPE_TOOBIG,
                                     0, mtu_value);

          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
          return TRUE;
        }
#endif /* WITH_IPV6 */

      SSH_DEBUG(SSH_D_UNCOMMON, ("MTU response not sent for protocol %d",
                                 pc->pp->protocol));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("MTU value %d is too low (< %d), MTU response not sent to dst %@",
             mtu_value, min_mtu_value, ssh_ipaddr_render, &pc->dst));
  return FALSE;
}

/* Check if the resulting packet will exceed the path MTU.
   Argument 'dont_fragment' is TRUE if the plaintext packet cannot
   be fragmented.  This Returns FALSE in the case where the
   transform processing should not continue, the packet should then
   be dropped. Otherwise returns TRUE. */
static Boolean
fastpath_transform_check_pmtu(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc,
                              SshUInt32 prefix_len,
                              SshUInt32 prefix_ofs,
                              Boolean dont_fragment)
{
  SshUInt32 pad_len, new_mtu, new_len;
  SshEngineTransformData d_trd;

  /* Determine number of padding bytes for trailer. */
  pad_len = 0;
  if (tc->trailer_len > 0)
    {
      pad_len = (pc->packet_len + prefix_len -
                 prefix_ofs - tc->esp_ofs - tc->esp_len + 2) %
        tc->pad_boundary;
      if (pad_len == 0)
        pad_len = 0;
      else
        pad_len = tc->pad_boundary - pad_len;
    }

  /* Calculate resulting packet length. */
  new_len = pc->packet_len + prefix_len + tc->trailer_len + pad_len;

  /* Set the number of bytes that are added to the packet after
     all transforms are performed. */
#ifdef SSH_IPSEC_TCPENCAP
  new_len += tc->tcp_encaps_len;
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IPSEC_HWACCEL
  /* A kludge for hardware accelerators which do not compute the
     padding length correctly for null ciphers. Force the the PMTU
     size to be 4 bytes smaller than it should be. */
  if (tc->transform_accel && (tc->transform & SSH_PM_CRYPT_NULL))
    new_len += 4;
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Check for overflow on packet size calculation. */
  if (new_len > 65535)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Resulting packet would be too big: new_len %u", new_len));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
      return FALSE;
    }

  /* Path MTU processing. If the packet got longer than mtu recorded
     into flow (next hop, or one received from the net) we possibly
     send ICMP fragneeded/toobig */
  if (new_len > pc->u.flow.mtu)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Resulting packet size %d exceeds flow MTU %d",
                 (unsigned int) new_len,
                 (unsigned int) pc->u.flow.mtu));

      /* This is a restarted outbound packet, update the pmtu value
         of the previous transform. */
      if ((pc->flags & SSH_ENGINE_PC_RESTARTED_OUT) != 0)
        {
          if (pc->prev_transform_index != SSH_IPSEC_INVALID_INDEX)
            {
              ssh_kernel_mutex_lock(fastpath->engine->flow_control_table_lock);
              d_trd = FASTPATH_GET_TRD(fastpath, pc->prev_transform_index);
              SSH_ASSERT(d_trd->transform != 0);

              new_mtu = pc->u.flow.mtu - (new_len - pc->u.flow.mtu);

              if (d_trd->pmtu_received == 0 || new_mtu < d_trd->pmtu_received)
                {
                  SSH_DEBUG(SSH_D_HIGHOK,
                            ("Updating PMTU of trd_index 0x%lx from %u to %u",
                             (unsigned long) pc->prev_transform_index,
                             (unsigned int) d_trd->pmtu_received,
                             (unsigned int) new_mtu));
                  d_trd->pmtu_received = (SshUInt16) new_mtu;



                  FASTPATH_COMMIT_TRD(fastpath, pc->prev_transform_index,
                                      d_trd);
                }
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("PMTU for trd 0x%lx is already lower: %d < %d",
                             (unsigned long) pc->prev_transform_index,
                             (unsigned int) d_trd->pmtu_received,
                             (unsigned int) new_mtu));
                  FASTPATH_RELEASE_TRD(fastpath, pc->prev_transform_index);
                }

              ssh_kernel_mutex_unlock(fastpath->engine->
                                      flow_control_table_lock);
            }

          /* Restarted outbound packets can always be fragmented after
             IPsec processing, as the packet is always locally generated. */
        }

      /* Send ICMP frag needed / ICMPv6 too big if
         plaintext packet cannot be fragmented (IPv6 or IPv4 with DF) and
         policy specifies either copy or set for DF bit. Otherwise the
         resulting cryptotext packet is fragmented after IPsec encapsulation.

         This strategy allows plaintext hosts to perform PMTU, and
         the df bit policy setting affects whether the tunnel is visible
         during this process. That is, SSH_ENGINE_DF_CLEAR policy must make
         the tunnel's packet enlargement invisible to the PMTU discovery.

         Note that df bit policy setting affects IPv6 too, though the
         values DF_KEEP and DF_SET are handled equally. */
      else if (dont_fragment == TRUE
               && pc->u.flow.trr->df_bit_processing != SSH_ENGINE_DF_CLEAR)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Fragmentation not allowed after IPsec processing: "
                     "df '%s' df policy '%s'",
                     (dont_fragment == TRUE ? "true" : "false"),
                     (pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_KEEP ?
                      "keep" :
                      (pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_SET ?
                       "set" : "clear"))));
          if (fastpath_transform_process_pmtu(fastpath, pc, tc,
                                              pc->transform))
            {
              /* Drop packet */
              return FALSE;
            }
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Fragmentation allowed after IPsec processing: "
                 "df '%s' df policy '%s'",
                 (dont_fragment == TRUE ? "true" : "false"),
                 (pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_KEEP ?
                  "keep" :
                  (pc->u.flow.trr->df_bit_processing == SSH_ENGINE_DF_SET ?
                   "set" : "clear"))));

#ifdef SSH_IPSEC_AH
      /* The packet is going to be fragmented after transform.
         Allocate an IPv4 IP ID if transport mode AH transform is going to
         be performed for the packet. */
      if ((pc->transform & SSH_PM_IPSEC_AH) != 0
          && (pc->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)) == 0)
        pc->u.flow.trr->myipid = ssh_engine_get_ip_id(fastpath->engine);
#endif /* SSH_IPSEC_AH */
    }

  /* Let packet pass on to IPsec encapsulation */
  return TRUE;
}

#ifdef SSHDIST_L2TP
static void
fastpath_transform_construct_l2tp_header(SshEnginePacketContext pc,
                                         SshFastpathTransformContext tc,
                                         unsigned char *ucpw,
                                         size_t ucpw_len,
                                         size_t *return_hdr_len)

{
  SshEngineTransformRun trr = pc->u.flow.trr;
  SshUInt16 orig_len = (SshUInt16)ssh_interceptor_packet_len(pc->pp);
  unsigned char *orig_ucpw = ucpw;

  SSH_ASSERT(orig_len == ssh_interceptor_packet_len(pc->pp));

  /* Check here that we won't overflow the 'ucpw' buffer */
  SSH_ASSERT(ucpw_len >= SSH_UDP_HEADER_LEN + 8 + 4 + 2 + 1 + 1);

  /* Construct L2TP UDP+PPP headers. */
  if (pc->transform & SSH_PM_IPSEC_L2TP)
    {
      /* Construct UDP header. */
      SSH_UDPH_SET_SRCPORT(ucpw, trr->l2tp_local_port);
      SSH_UDPH_SET_DSTPORT(ucpw, trr->l2tp_remote_port);
      SSH_UDPH_SET_LEN(ucpw, orig_len + tc->prefix_len - tc->l2tp_ofs);
      /* SSH_UDPH_SET_CHECKSUM(ucpw, 0); (implicit by memset earlier) */

      /* Construct L2TP header. */





      ucpw += SSH_UDP_HEADER_LEN;
      SSH_L2TPH_SET_VERSION_AND_BITS(ucpw,
                                     SSH_L2TP_DATA_MESSAGE_HEADER_VERSION,
                                     SSH_L2TPH_F_LENGTH);
      SSH_PUT_16BIT(ucpw + 2, orig_len + tc->prefix_len - tc->l2tp_ofs -
                    SSH_UDP_HEADER_LEN);
      SSH_PUT_16BIT(ucpw + 4, trr->l2tp_remote_tunnel_id);
      SSH_PUT_16BIT(ucpw + 6, trr->l2tp_remote_session_id);
      ucpw += 8;

      if (trr->l2tp_flags & SSH_ENGINE_L2TP_SEQ)
        {
          /* Set sequence numbers. */
          SSH_PUT_16BIT(ucpw, trr->l2tp_seq_ns);
          SSH_PUT_16BIT(ucpw + 2, trr->l2tp_seq_nr);
          ucpw += 4;
        }

      /* Construct PPP header. */
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_ACFC) == 0)
        {
          SSH_PUT_16BIT(ucpw, 0xff03);
          ucpw += 2;
        }
      if ((trr->l2tp_flags & SSH_ENGINE_L2TP_PPP_PFC) == 0)
        {
          /* SSH_PUT_8BIT(ucpw, 0); (already zeroed by memset above) */
          ucpw++;
        }
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        SSH_PUT_8BIT(ucpw, SSH_PPP_PROTO_IPV6);
      else
#endif /* WITH_IPV6 */
        SSH_PUT_8BIT(ucpw, SSH_PPP_PROTO_IP);
    }

  if (return_hdr_len)
    *return_hdr_len = (size_t)(ucpw - orig_ucpw) + 1;
}
#endif /* SSHDIST_L2TP */

static void
fastpath_transform_out_update_pc(SshFastpathTransformContext tc,
                                 SshEnginePacketContext pc)
{
  /* Update packet length. */
  pc->packet_len = ssh_interceptor_packet_len(pc->pp);

  /* Update information after tunneling. */
  if (tc->prefix_at_0)
    {
      /* Reassign src and dst ip numbers to that of the tunnel. */
      pc->dst = pc->u.flow.trr->gw_addr;
      pc->src = pc->u.flow.trr->local_addr;

      /* Clear packet context flags.  Otherwise they might, e.g.,
         prevent fragmenting the packet if it were too big. */
      pc->pp->flags &= SSH_ENGINE_P_RESET_MASK;

#if defined (WITH_IPV6)
      if (SSH_IP_IS6(&pc->u.flow.trr->gw_addr))
        {
          pc->pp->protocol = SSH_PROTOCOL_IP6;
          pc->hdrlen = SSH_IPH6_HDRLEN;

          /* Store also `pc->ipsec_offset' and
             `pc->ipsec_offset_prevnh' in case we're going to do
             nested tunnels some day. */
          pc->ipsec_offset = SSH_IPH6_HDRLEN;
          pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;
        }
      else
#endif /* WITH_IPV6 */
        {
          pc->pp->protocol = SSH_PROTOCOL_IP4;
          pc->hdrlen = SSH_IPH4_HDRLEN;
        }
    }

  /* Allow fragmentation after IPsec encapsulation */
  pc->pp->flags |= SSH_PACKET_FRAGMENTATION_ALLOWED;

















}

static void
fastpath_transform_out_fail(SshFastpath fastpath,
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


/**************** Forward declarations of outbound transform handlers ********/

#ifdef SSHDIST_IPSEC_HWACCEL
/* Perform last step of outbound hardware accelerated combined IPsec
   transform. This function completes outbound transform processing for
   the packet. */
static void
fastpath_transform_out_finish_hw_combined(SshInterceptorPacket pp,
                                          SshHWAccelResultCode result,
                                          void *context);

/* Perform next step of outbound IPsec transform after hardware accelerated
   encryption. This function performs MAC computation for the packet in
   hardware or software, unless MAC is already computed.  */
static void
fastpath_transform_out_finish_hw_enc(SshInterceptorPacket pp,
                                     SshHWAccelResultCode result,
                                     void *context);

/* Perform last step of outbound IPsec transform after hardware accelerated
   or software MAC computation. This function completes outbound transform
   processing for the packet. */
static void
fastpath_transform_out_finish_hw_mac(SshInterceptorPacket pp,
                                     SshHWAccelResultCode result,
                                     void *context);

/* Insert the most significant 32 bits of the sequence number to the packet
   if using 64 bit sequence numbers.*/
static Boolean
fastpath_transform_out_append_seq_high(SshEnginePacketContext pc);

#endif /* SSHDIST_IPSEC_HWACCEL */

/* Perform software encryption and MAC computation when combined mode
   algorithm is selected. */
static void
fastpath_transform_out_sw_combined(SshFastpath fastpath,
                                   SshFastpathTransformContext tc,
                                   SshEnginePacketContext pc,
                                   size_t enc_ofs, size_t enc_len);

/* Perform software encryption. */
static void
fastpath_transform_out_sw_enc(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc,
                              size_t enc_ofs, size_t enc_len);

/* Perform software MAC computation. */
static void
fastpath_transform_out_sw_mac(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc);

/* This function starts MAC computation by passing packet to software MAC
   computation or hardware acceleration. */
static void
fastpath_transform_out_start_mac(SshFastpath fastpath,
                                 SshFastpathTransformContext tc,
                                 SshEnginePacketContext pc);

/* Performs the last part of the outgoing IP transform implementation. */
static void
fastpath_transform_out_finish(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc);

/*********************** Outbound transform start ****************************/

/* Implements outgoing IPsec transforms for outgoing IP packets.  This
   function implements AH, ESP, IPCOMP, L2TP, NAT Traversal, and
   IP-in-IP (for tunnel mode) transforms. This calls the callback when
   done (either during the call to this function or at some later time).
   This function may use hardware acceleration to perform its work.
   When this is called, the packet has already gone through basic sanity
   checks, and we know that it has at least hdrlen+8 bytes of data. */

void ssh_fastpath_transform_out(SshFastpath fastpath,
                                SshEnginePacketContext pc,
                                SshEngineTransformRun trr,
                                SshFastpathTransformCB callback,
                                void *context)
{
  SshUInt32 new_len, pad_len, i, prefix_ofs, len;
  SshUInt16 prefix_len, enc_ofs = 0, mac_ofs = 0, enc_len, mac_len, ipid;
  SshFastpathTransformContext tc;
  unsigned char *ucpw;
  unsigned char prefix[SSH_ENGINE_MAX_TRANSFORM_PREFIX];
  SshUInt16 cks, fragoff;
  SshUInt8 tos, ttl;
  SshUInt16 orig_len, old_len;
  unsigned char orig_ip_nh = pc->ipproto;
#ifdef SSHDIST_IPSEC_NAT
  Boolean forward;
#endif /* SSHDIST_IPSEC_NAT */
#if defined (WITH_IPV6)
  SshUInt32 flow_label = 0;
#endif /* WITH_IPV6 */
  Boolean dont_fragment, ipcomp_done;
  SshUInt8 esp_nh;
#ifdef SSH_IPSEC_AH
  SshUInt8 ah_nh;
#endif /* SSH_IPSEC_AH */
#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  SshFastpathTransformIpcompState ipcomp_state;
  SshFastpathTransformIpcompStatus ipcomp_status;
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Outbound transform processing entered"));

  /* Save callback function for later use. */
  pc->u.flow.tr_callback = callback;
  pc->u.flow.tr_context = context;

  /* Save the transform run-time data pointer. */
  pc->u.flow.trr = trr;
  pc->u.flow.crypto_state = 0;

  /* Obtain a transform context for the transform.  This may come from
     a cache or might be constructed here. */
  pc->u.flow.tc =
    ssh_fastpath_get_transform_context(fastpath, trr, pc, TRUE,
                                       pc->pp->protocol == SSH_PROTOCOL_IP6,
                                       SSH_IP_IS6(&trr->gw_addr));
  if (pc->u.flow.tc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Allocating transform context failed"));
      /* Failed to allocate action context. */
      goto fail;
    }
  tc = pc->u.flow.tc;

  ipcomp_done = FALSE;
  orig_len = (SshUInt16) pc->packet_len;
#ifdef SSH_IPSEC_AH
  ah_nh = tc->ah_nh;
#endif /* SSH_IPSEC_AH */
  esp_nh = tc->esp_nh;
  prefix_len = tc->prefix_len;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Read some needed fields from the old (inner) header.  Note that
     we pull it up in write mode, so that we can modify it below if
     appropriate. */
#if defined (WITH_IPV6)
  /* In IPv6 we're interested only in the hop limit and traffic
     class, which reside in the first two words. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
  else
#endif /* WITH_IPV6 */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
  if (!ucpw)
    {
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
      goto error;
    }

#if defined (WITH_IPV6)
  /* IPv6 case, use the variable `tos' for the traffic class. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      SSH_ASSERT(pc->packet_len == SSH_IPH6_LEN(ucpw) + SSH_IPH6_HDRLEN);
      tos = SSH_IPH6_CLASS(ucpw);
      flow_label = SSH_IPH6_FLOW(ucpw);
      if (pc->pp->flags & SSH_ENGINE_P_ISFRAG)
        fragoff = pc->fragment_offset;
      else
        fragoff = 0;
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_ASSERT(pc->packet_len == SSH_IPH4_LEN(ucpw));
      tos = SSH_IPH4_TOS(ucpw);
      fragoff = SSH_IPH4_FRAGOFF(ucpw);
      SSH_ASSERT(pc->ipproto == SSH_IPH4_PROTO(ucpw));
    }

  /* Determine the offset at which to insert headers. */
  if (tc->prefix_at_0)
    {
      prefix_ofs = 0;
    }
  else
    {
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        prefix_ofs = pc->ipsec_offset;
      else
#endif /* WITH_IPV6 */
        prefix_ofs = pc->hdrlen;
    }

  /* Check if fragmentation is allowed for the packet:

     Fragmentation is allowed if
     a) stack has indicated it
     b) packet has been reassembled because of transport mode
     c) otherwise if packet is IPv4 with DF bit cleared
  */
  if ((pc->pp->flags & SSH_PACKET_FRAGMENTATION_ALLOWED) == 0
      && ((pc->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)) != 0
          || (pc->pp->flags & SSH_ENGINE_P_WASFRAG) == 0)
      && ((pc->pp->protocol == SSH_PROTOCOL_IP4
           && (fragoff & SSH_IPH4_FRAGOFF_DF) != 0)
          || pc->pp->protocol == SSH_PROTOCOL_IP6))
    dont_fragment = TRUE;
  else
    dont_fragment = FALSE;

  /* Check if the resulting packet will exceed the path MTU. Do this now
     for transform level hardware acceleration. Postpone this check for
     other cases until after software IPComp is performed. */
  if (tc->transform_accel)
    {
      if (!fastpath_transform_check_pmtu(fastpath, tc, pc, prefix_len,
                                         prefix_ofs, dont_fragment))
        goto fail;
    }

  /* If this packet does not have IPv4 header checksum computed, i.e. the
     checksum should be computed by NIC, clear the flag and compute the
     IPv4 header checksum before encryption. */
  if (pc->pp->flags & SSH_PACKET_IP4HHWCKSUM)
    {
      SshUInt16 cksum = 0;

      SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP4);

      SSH_DEBUG(SSH_D_LOWOK, ("Computing IPv4 checksum"));

      ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
      if (ucpw == NULL)
        goto fail;

      SSH_IPH4_SET_CHECKSUM(ucpw, 0);
      cksum = ssh_ip_cksum(ucpw, pc->hdrlen);
      SSH_IPH4_SET_CHECKSUM(ucpw, cksum);

      pc->pp->flags &= ~SSH_PACKET_IP4HHWCKSUM;
    }

  /* If this packet does not have the TCP/UDP checksum computed, i.e. the
     checksum should be computed by the NIC device, then we need to clear
     this flag and compute the upper layer checksum before encryption. */
  if (pc->pp->flags & SSH_PACKET_HWCKSUM)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Computing TCP/UDP checksum"));

      if (!ssh_ip_cksum_packet_compute(pc->pp, 0, pc->hdrlen))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot compute checksum, dropping packet"));
          goto error;
        }
      pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Perform NAT transform. */
  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;
  if (ssh_fastpath_transform_nat(fastpath, pc, forward) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("NAT in outbound transform failed!"));
      goto fail;
    }

  /* ssh_fastpath_transform_nat() may invalidate the ucpw pointer
     for pullup, so we need to refetch it. */
#if defined (WITH_IPV6)
  /* In IPv6 we're interested only in the hop limit and traffic
     class, which reside in the first two words. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
  else
#endif /* WITH_IPV6 */
    ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);

  if (ucpw == NULL)
    goto error;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_STATISTICS
  /* Update statistics. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ESP_OUT);
    }
#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_AH_OUT);
    }
#endif /* SSH_IPSEC_AH */
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSHDIST_IPSEC_HWACCEL
  /* If we have transform-level acceleration context, use it now. */
  if (tc->transform_accel)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware combined transform"));

      ssh_hwaccel_perform_combined(tc->transform_accel,
                                   pc->pp,
                                   fastpath_transform_out_finish_hw_combined,
                                   (void *) pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Update the TTL in the IP header if doing tunnel mode. */
  if (tc->prefix_at_0)
    {
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          if (pc->flags & SSH_ENGINE_PC_DECREMENT_TTL)
            {
              ttl = SSH_IPH6_HL(ucpw);
              ttl--;
              if (ttl == 0)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("Hop limit reached zero"));
                  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
                  goto fail;
                }
              SSH_IPH6_SET_HL(ucpw, ttl);
            }
        }
      else
#endif /* WITH_IPV6 */
        if (pc->flags & SSH_ENGINE_PC_DECREMENT_TTL)
          {
            ttl = SSH_IPH4_TTL(ucpw);
            ttl--;
            if (ttl == 0)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TTL reached zero"));
                SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
                goto fail;
              }
            SSH_IPH4_SET_TTL(ucpw, ttl);
            cks = SSH_IPH4_CHECKSUM(ucpw);
            cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_TTL,
                                           ttl + 1, ttl);
            SSH_IPH4_SET_CHECKSUM(ucpw, cks);
          }
    }

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  /* Try to perform IPComp transformation. */
  if (pc->transform & SSH_PM_IPSEC_IPCOMP)
    {
      ipcomp_state = ssh_fastpath_ipcomp_state(pc, tc);

      if (ipcomp_state == SSH_FASTPATH_TRANSFORM_NO_COMPRESS)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Compression cannot be performed, "
                                  "omitting IPComp processing"));

          /* No IPComp header will be inserted, update the prefix length
             of the packet and the ESP/AH next headers. */
          prefix_len -= 4;
#ifdef SSH_IPSEC_AH
          if (ah_nh == SSH_IPPROTO_IPPCP)
            ah_nh = tc->ipcomp_nh;
#endif /* SSH_IPSEC_AH */
          if (esp_nh == SSH_IPPROTO_IPPCP)
            esp_nh = tc->ipcomp_nh;
#ifdef SSH_IPSEC_STATISTICS
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NOIPCOMP_OUT);
#endif /* SSH_IPSEC_STATISTICS */
        }
      else if (ipcomp_state == SSH_FASTPATH_TRANSFORM_DO_COMPRESS)
        {
          unsigned char *extra = NULL;
          size_t extra_len = 0;

#ifdef SSHDIST_L2TP
          /* Construct L2TP UDP+PPP headers. */
          if (pc->transform & SSH_PM_IPSEC_L2TP)
            {
              /* Zero the inserted data so that all reserved bytes
                 get zeroed. */
              SSH_ASSERT(prefix_len < SSH_ENGINE_MAX_TRANSFORM_PREFIX);
              memset(prefix, 0, prefix_len);

              fastpath_transform_construct_l2tp_header(pc, tc,
                                                       prefix, sizeof(prefix),
                                                       &extra_len);
              extra = prefix;
            }
#endif /* SSHDIST_L2TP */

          /* And do the IPcomp operation */
          ipcomp_status = ssh_fastpath_transform_ipcomp_outbound(pc, tc,
                                                                 prefix_ofs,
                                                                 extra,
                                                                 extra_len);
          switch (ipcomp_status)
            {
            case SSH_FASTPATH_IPCOMP_DROP:
            case SSH_FASTPATH_IPCOMP_NO_MEMORY:
              SSH_DEBUG(SSH_D_FAIL, ("IPcomp operation failed"));
              goto error;

            case SSH_FASTPATH_IPCOMP_SUCCESS:
              SSH_DEBUG(SSH_D_MY, ("IPComp operation result success"));
              /* Update the prefix length by reducing the length of the
                 L2TP+UDP+PPP headers as these are now compressed. */
              prefix_len -= (SshUInt16)extra_len;
              ipcomp_done = TRUE;
              break;

            case SSH_FASTPATH_IPCOMP_PASSBY:
              SSH_DEBUG(SSH_D_MY, ("IPComp operation result passby"));
              /* No IPComp header was be inserted, update the prefix length
                 of the packet and the ESP/AH next headers. */
              prefix_len -= 4;
#ifdef SSH_IPSEC_AH
              if (ah_nh == SSH_IPPROTO_IPPCP)
                ah_nh = tc->ipcomp_nh;
#endif /* SSH_IPSEC_AH */
              if (esp_nh == SSH_IPPROTO_IPPCP)
                esp_nh = tc->ipcomp_nh;
              break;
            }
        }
      else
        SSH_NOTREACHED;
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

  /* Zero the inserted data so that all reserved bytes get zeroed. */
  SSH_ASSERT(prefix_len < SSH_ENGINE_MAX_TRANSFORM_PREFIX);
  memset(prefix, 0, prefix_len);

  /* Compression is done. Now we can compute the length of the final
     packet, padding length etc. */
  old_len = (SshUInt16) pc->packet_len;
  SSH_ASSERT(old_len == ssh_interceptor_packet_len(pc->pp));

  /* Determine number of padding bytes for trailer. */
  pad_len = 0;
  if (tc->trailer_len > 0)
    {
      pad_len = ((pc->packet_len + prefix_len -
                  prefix_ofs - tc->esp_ofs - tc->esp_len + 2) %
                 tc->pad_boundary);
      if (pad_len == 0)
        pad_len = 0;
      else
        pad_len = tc->pad_boundary - pad_len;
    }

  /* Calculate resulting packet length and save the input packet
     length. */
  new_len = pc->packet_len + prefix_len + tc->trailer_len + pad_len;

  /* Check if the resulting packet will exceed the path MTU */
  if (!fastpath_transform_check_pmtu(fastpath, tc, pc, prefix_len,
                                     prefix_ofs, dont_fragment))
    goto fail;

  if (!tc->prefix_at_0)
    {
      /* We are processing the packet in transport mode; modify the
         ipproto field of the IP header and update packet length in
         its header. */
#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, 8);
          if (ucpw == NULL)
            goto error;

          SSH_IPH6_SET_LEN(ucpw, new_len - SSH_IPH6_HDRLEN);
          ssh_interceptor_packet_copyout(pc->pp, pc->ipsec_offset_prevnh,
                                         &orig_ip_nh, 1);
          if (!ssh_interceptor_packet_copyin(pc->pp, pc->ipsec_offset_prevnh,
                                             &tc->ip_nh, 1))
            goto error;
        }
      else
#endif /* WITH_IPV6 */
        {
          ucpw = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen);
          if (ucpw == NULL)
            goto error;

          SSH_IPH4_SET_PROTO(ucpw, tc->ip_nh);
          SSH_IPH4_SET_LEN(ucpw, new_len);
          ipid = SSH_IPH4_ID(ucpw);
          if (ipid == 0)
            SSH_IPH4_SET_ID(ucpw, trr->myipid);
          cks = SSH_IPH4_CHECKSUM(ucpw);
          cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_PROTO,
                                         pc->ipproto, tc->ip_nh);
          cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_LEN, orig_len,
                                          (SshUInt16)new_len);
          if (ipid == 0)
            cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_ID, 0,
                                            trr->myipid);
          SSH_IPH4_SET_CHECKSUM(ucpw, cks);
        }
    }

  /* Check and audit for sequence number overflow. */
  if ((pc->transform & SSH_PM_IPSEC_ANTIREPLAY)
      && (((pc->transform & SSH_PM_IPSEC_LONGSEQ)
           && SSH_UINT64_OVERFLOW(trr->mycount_low, trr->mycount_high))
          || (!(pc->transform & SSH_PM_IPSEC_LONGSEQ)
              && trr->mycount_low == 0xffffffff)))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Sequence number overflow detected, dropping packet."));
#ifdef SSH_IPSEC_AH
      if (pc->transform & SSH_PM_IPSEC_AH)
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_OVERFLOW;
          pc->audit.spi = trr->myspis[SSH_PME_SPI_AH_IN];
        }
      else
#endif /* SSH_IPSEC_AH */
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_OVERFLOW;
          pc->audit.spi = trr->myspis[SSH_PME_SPI_ESP_IN];
        }
      pc->audit.ip_option = 0;
      pc->audit.seq = 0xffffffff;

      goto fail;
    }

  /* Store sequence numbers into the packet. */
  pc->u.flow.seq_num_low = trr->mycount_low;
  pc->u.flow.seq_num_high = trr->mycount_high;

  /* Fill in the ESP header.  We also compute the offsets for
     encryption and MAC computation here. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      ucpw = prefix + tc->esp_ofs;
      SSH_ESPH_SET_SPI(ucpw, trr->myspis[SSH_PME_SPI_ESP_IN]);

      /* If using 64 bit sequence numbers, only the least significant
         32 bits are sent to the peer. */
      SSH_ESPH_SET_SEQ(ucpw, pc->u.flow.seq_num_low);

      enc_ofs = prefix_ofs + tc->esp_ofs + SSH_ESPH_HDRLEN;
      enc_len = old_len + prefix_len - enc_ofs + pad_len + 2;
      mac_ofs = prefix_ofs + tc->esp_ofs;
      mac_len = new_len - mac_ofs - tc->icv_len;
    }
  else
    {
      enc_len = 0;
      mac_len = 0;
    }
  pc->u.flow.mac_icv_ofs = 0;

#ifdef SSH_IPSEC_AH
  /* Fill in AH header and adjust MAC ofs/len as needed. */
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      /* Fill in AH header. */
      ucpw = prefix + tc->ah_ofs;
      SSH_AHH_SET_NH(ucpw, ah_nh ? ah_nh : pc->ipproto);
      SSH_AHH_SET_LEN(ucpw, (tc->icv_len + 12 + tc->ah_hdr_pad_len) / 4 - 2);
      SSH_AHH_SET_SPI(ucpw, tc->ah_spi);
      pc->u.flow.mac_icv_ofs = prefix_ofs + tc->ah_ofs + SSH_AHH_MINHDRLEN;

      /* Zeroify the padding bytes */
      if (tc->ah_hdr_pad_len > 0)
        {
          for (i = 0; i < tc->ah_hdr_pad_len; i++)
            ucpw[SSH_AHH_MINHDRLEN + tc->icv_len + i] = 0;
        }

      /* If using 64 bit sequence numbers, only the least significant
         32 bits are sent to the peer. */
      SSH_AHH_SET_SEQ(ucpw, pc->u.flow.seq_num_low);

      /* Recompute what to include in MAC. */
      mac_ofs = prefix_ofs + tc->ah_ofs;
      mac_len = new_len - mac_ofs;

      /* IP header is automatically added to the MAC, and the IP
         length in the IP header is automatically adjusted by the
         difference between the end of the IP header and the given
         offset, and IPPROTO in the IP header is automatically taken
         as SSH_IPPROTO_AH regardless of what it is (it could be UDP
         if NAT-T is used). */
    }
#endif /* SSH_IPSEC_AH */

  /* Update packet length in packet context. */
  pc->packet_len = new_len;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* This code does not use the fastpath_transform_add_natt_header on
     purpose.  Doing the minimal work here is faster. */

  /* Construct NAT Traversal header. */
  if (pc->transform & SSH_PM_IPSEC_NATT)
    {
      /* Only ESP is supported by the latest drafts and RFC. */
      SSH_ASSERT((pc->transform & SSH_PM_IPSEC_AH) == 0);

      /* Fill in NAT Traversal UDP header. */
      ucpw = prefix + tc->natt_ofs;
      SSH_UDPH_SET_SRCPORT(ucpw, trr->local_port);
      SSH_UDPH_SET_DSTPORT(ucpw, trr->remote_port);
      SSH_UDPH_SET_LEN(ucpw, pc->packet_len - tc->natt_ofs - prefix_ofs);
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSHDIST_IPSEC_IPCOMP
#ifdef SSH_IPSEC_IPCOMP_IN_SOFTWARE
  /* Add an IPComp header if compression succeeded. */
  if ((pc->transform & SSH_PM_IPSEC_IPCOMP) && ipcomp_done)
    {
      ucpw = prefix + tc->ipcomp_ofs;
      ucpw[0] = tc->ipcomp_nh ? tc->ipcomp_nh : pc->ipproto;
      ucpw[1] = 0;
      SSH_PUT_16BIT(ucpw + 2, tc->ipcomp_cpi);
    }
#endif /* SSH_IPSEC_IPCOMP_IN_SOFTWARE */
#endif /* SSHDIST_IPSEC_IPCOMP */

#ifdef SSHDIST_L2TP
  /* Construct L2TP UDP+PPP headers. However if IPcomp compression
     succeeded the L2TP headers are already compressed and should not be
     added. */
  if ((pc->transform & SSH_PM_IPSEC_L2TP) && !ipcomp_done)
    {
      SshUInt8 l2tp_ofs = tc->l2tp_ofs;

      if (pc->transform & SSH_PM_IPSEC_IPCOMP)
        {
          /* The offset of the L2TP header is 4 less than the the value
             in tc->l2tp_ofs if we get here (IPcomp compression did not
             succeed and there is no IPComp header) */
          l2tp_ofs -= 4;
        }

      fastpath_transform_construct_l2tp_header(pc, tc, prefix + l2tp_ofs,
                                               sizeof(prefix) - l2tp_ofs,
                                               NULL);
    }
#endif /* SSHDIST_L2TP */

  /* Fill in new IP header for tunneling. */
  if (tc->prefix_at_0)
    {
      /* Construct a new IP header.  It is always at the beginning of
         the prefix. */
#if defined (WITH_IPV6)
      if (SSH_IP_IS6(&trr->gw_addr))
        {
          /* Construct a new IPv6 header. */
          SSH_IPH6_SET_VERSION(prefix, 6);

          /* We should map the IPv4 Type of Service to IPv6 Traffic
             Class but since no such mapping exists, we follow RFC
             2473 and use pre-defined value 0. */
          if (pc->pp->protocol == SSH_PROTOCOL_IP4)
            tos = 0;







          SSH_IPH6_SET_CLASS(prefix, tos);
          SSH_IPH6_SET_FLOW(prefix, flow_label);
          SSH_IPH6_SET_LEN(prefix, new_len - SSH_IPH6_HDRLEN);
          SSH_IPH6_SET_NH(prefix, tc->ip_nh);
          SSH_IPH6_SET_HL(prefix, 240);
          SSH_IPH6_SET_SRC(&trr->local_addr, prefix);
          SSH_IPH6_SET_DST(&trr->gw_addr, prefix);

          /* Initialize IPv6-specific fields in the packet context in
             case we should have to, e.g. fragment this packet. */
          pc->fragh_offset = pc->ipsec_offset = SSH_IPH6_HDRLEN;
          pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;
        }
      else
#endif /* WITH_IPV6 */
        {
          /* Construct the new IPv4 header. */
          SSH_IPH4_SET_VERSION(prefix, 4);
          SSH_IPH4_SET_HLEN(prefix, SSH_IPH4_HDRLEN / 4);
#if defined (WITH_IPV6)
          /* We should map the IPv6 Traffic Class to TOS but since
             no such mapping exists, we follow RFC 2473 and use
             pre-defined value 0. */
          if (pc->pp->protocol == SSH_PROTOCOL_IP6)
            tos = 0;
#endif /* WITH_IPV6 */
          SSH_IPH4_SET_TOS(prefix, tos);
          SSH_IPH4_SET_ID(prefix, trr->myipid);

          /* Copy DF and RF bits from the original header.*/
          fragoff &= (SSH_IPH4_FRAGOFF_DF | SSH_IPH4_FRAGOFF_RF);
          SSH_IPH4_SET_FRAGOFF(prefix, fragoff);

          SSH_IPH4_SET_TTL(prefix, 240); /* Outer header TTL. */
          SSH_IPH4_SET_SRC(&trr->local_addr, prefix);
          SSH_IPH4_SET_DST(&trr->gw_addr, prefix);
          SSH_IPH4_SET_PROTO(prefix, tc->ip_nh);
          SSH_IPH4_SET_LEN(prefix, pc->packet_len); /* Set new packet length */

          /* SSH_IPH4_SET_CHECKSUM(prefix, 0);
             (done implicitly by memset earlier) */
          cks = ssh_ip_cksum(prefix, SSH_IPH4_HDRLEN);
          SSH_IPH4_SET_CHECKSUM(prefix, cks);
        }
    }

  /* Insert the prefix into the packet. */
  for (i = 0; i < prefix_len; i += len)
    {
      len = 80;
      if (i + len > prefix_len)
        len = prefix_len - i;
      ucpw = ssh_interceptor_packet_insert(pc->pp, prefix_ofs + i, len);
      if (ucpw == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Prefix insert failed"));
          goto error;
        }
      memcpy(ucpw, prefix + i, len);
    }

  /* Insert ESP trailer (padding and MAC). */
  if (tc->trailer_len > 0)
    {
      i = old_len + prefix_len;
      SSH_ASSERT(i == ssh_interceptor_packet_len(pc->pp));
      SSH_ASSERT(tc->trailer_len + pad_len <= 80);
      ucpw = ssh_interceptor_packet_insert(pc->pp, i,
                                           tc->trailer_len + pad_len);
      if (ucpw == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Trailer insert failed"));
          goto error;
        }

      /* Initialize self-describing. */
      for (i = 0; i < pad_len; i++)
        ucpw[i] = i + 1;
      ucpw[i++] = (SshUInt8) pad_len;
      ucpw[i++] = esp_nh ? esp_nh : orig_ip_nh;
    }

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));

  /* Determine mac_icv_ofs if not already done. */
  if (pc->u.flow.mac_icv_ofs == 0)
    pc->u.flow.mac_icv_ofs = pc->packet_len - tc->icv_len;

  SSH_DUMP_PACKET(SSH_D_PCKDMP, "Plaintext:", pc->pp);

  /* Save enough data to perform after encryption in callback. */
  pc->u.flow.mac_ofs = mac_ofs;
  pc->u.flow.mac_len = mac_len;

#ifdef SSHDIST_IPSEC_HWACCEL
  /* Perform encryption and authentication computations. */







  if (tc->encmac_accel)
    {
      /* If using 64 bit sequence numbers, insert the most significant
         32 bits of the sequence number to the packet. The data gets
         removed in fastpath_transform_out_finish_hw_enc. */
      if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          if (!fastpath_transform_out_append_seq_high(pc))
            goto error;
        }

      /* Use hardware acceleration to perform the rest. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware encryption and MAC"));

      ssh_hwaccel_perform_ipsec(tc->encmac_accel, pc->pp, enc_ofs, enc_len,
                                pc->u.flow.mac_ofs, pc->u.flow.mac_len,
                                pc->u.flow.mac_icv_ofs,
                                fastpath_transform_out_finish_hw_enc,
                                (void *)pc);
      return;
    }

  if (tc->enc_accel)
    {
      /* Use hardware acceleration to perform encryption, and then
         perform MAC computation in software. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware encryption"));

      ssh_hwaccel_perform_ipsec(tc->enc_accel, pc->pp, enc_ofs, enc_len,
                                0, 0, 0,
                                fastpath_transform_out_finish_hw_enc,
                                (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing software IPsec transform"));

  /* Select appropriate outbound transform handler. */
  if (tc->with_sw_cipher && tc->with_sw_auth_cipher)
    fastpath_transform_out_sw_combined(fastpath, tc, pc, enc_ofs, enc_len);
  else if (tc->with_sw_cipher)
    fastpath_transform_out_sw_enc(fastpath, tc, pc, enc_ofs, enc_len);
  else
    fastpath_transform_out_start_mac(fastpath, tc, pc);

  return;

 fail:
  fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_FAIL);
  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
  return;
}


#ifdef SSHDIST_IPSEC_HWACCEL
/************** Hardware accelerated outbound transform handler **************/

/* Append the higher part of an extended sequence number to packet data
   if the transform specifies ESN (Using 64 bit sequence numbers).
   For ESP insert the data at the end of the payload just before the ICV,
   for AH insert at the end of the payload. The higher order bits of the
   sequence number are included in the ICV computation but do not get
   encrypted. Also they are not sent on the wire. */
static Boolean
fastpath_transform_out_append_seq_high(SshEnginePacketContext pc)
{
  unsigned char *ucpw;
  size_t longseq_ofs = 0;

  if (pc->transform & SSH_PM_IPSEC_ESP)
    longseq_ofs = pc->u.flow.mac_icv_ofs;
#ifdef SSH_IPSEC_AH
  else if (pc->transform & SSH_PM_IPSEC_AH)
    longseq_ofs = pc->packet_len;
#endif /* SSH_IPSEC_AH */
  else
    return TRUE;

  ucpw = ssh_interceptor_packet_insert(pc->pp, longseq_ofs, 4);
  if (!ucpw)
    return FALSE;

  SSH_PUT_32BIT(ucpw, pc->u.flow.seq_num_high);
  pc->u.flow.mac_len += 4;
  pc->packet_len += 4;

  if (!(pc->transform & SSH_PM_IPSEC_AH))
    pc->u.flow.mac_icv_ofs += 4;

  return TRUE;
}

static Boolean
fastpath_transform_out_delete_seq_high(SshFastpathTransformContext tc,
                                       SshEnginePacketContext pc)
{
  size_t longseq_ofs = 0;

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    longseq_ofs = pc->packet_len - tc->icv_len - 4;
#ifdef SSH_IPSEC_AH
  else if (pc->transform & SSH_PM_IPSEC_AH)
    longseq_ofs = pc->packet_len - 4;
#endif /* SSH_IPSEC_AH */
  else
    return TRUE;

  if (!ssh_interceptor_packet_delete(pc->pp, longseq_ofs, 4))
    return FALSE;

  pc->packet_len -= 4;

  return TRUE;
}

/* Perform last step of outbound hardware accelerated combined IPsec
   transform. This function completes outbound transform processing for
   the packet. */
static void
fastpath_transform_out_finish_hw_combined(SshInterceptorPacket pp,
                                          SshHWAccelResultCode result,
                                          void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(pc->u.flow.tc->transform_accel != NULL);

  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp)
        ssh_interceptor_packet_free(pp);

      goto error;
    }

  pc->pp = pp;

  /* Update information after tunneling. */
  fastpath_transform_out_update_pc(pc->u.flow.tc, pc);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if ((pc->transform & SSH_PM_IPSEC_NATT) &&
      (pc->u.flow.tc->accel_unsupported_mask & SSH_HWACCEL_COMBINED_FLAG_NATT))
    {
      /* It can't do the requested nat-t, we do it now. */
      if (!fastpath_transform_add_natt_header(pc->u.flow.tc, pc))
        goto error;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Set outer header df-bit on IPv4 packets. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP4
      && pc->u.flow.trr->df_bit_processing != SSH_ENGINE_DF_KEEP)
    {
      if (!fastpath_transform_process_df(pc))
        goto error;
    }

  fastpath_transform_out_finish(pc->engine->fastpath, pc->u.flow.tc, pc);
  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(pc->engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
}

/* Perform next step of outbound IPsec transform after hardware accelerated
   encryption. This function performs MAC computation for the packet in
   hardware or software, unless MAC is already computed.  */
static void
fastpath_transform_out_finish_hw_enc(SshInterceptorPacket pp,
                                     SshHWAccelResultCode result,
                                     void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc = pc->u.flow.tc;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(tc->transform_accel == NULL);
  SSH_ASSERT(tc->encmac_accel != NULL || tc->enc_accel != NULL);

  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp)
        ssh_interceptor_packet_free(pp);

      goto error;
    }

  pc->pp = pp;

  if (tc->encmac_accel)
    {
      /* Update packet context information after tunneling. */
      fastpath_transform_out_update_pc(tc, pc);

      /* Set outer header df-bit on IPv4 packets. */
      if (pc->pp->protocol == SSH_PROTOCOL_IP4
          && pc->u.flow.trr->df_bit_processing != SSH_ENGINE_DF_KEEP)
        {
          if (!fastpath_transform_process_df(pc))
            goto error;
        }

      /* If using 64 bit sequence numbers, remove the most significant
         32 bits of the sequence number that was previously inserted to
         the packet. */
      if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          if (!fastpath_transform_out_delete_seq_high(tc, pc))
            goto error;
        }

      fastpath_transform_out_finish(pc->engine->fastpath, tc, pc);
    }
  else
    {
      fastpath_transform_out_start_mac(pc->engine->fastpath, tc, pc);
    }

  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(pc->engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
}

/* Perform last step of outbound IPsec transform after hardware accelerated
   or software MAC computation. This function completes outbound transform
   processing for the packet. */
static void
fastpath_transform_out_finish_hw_mac(SshInterceptorPacket pp,
                                     SshHWAccelResultCode result,
                                     void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshFastpathTransformContext tc = pc->u.flow.tc;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(tc->transform_accel == NULL);
  SSH_ASSERT(tc->mac_accel != NULL);

  if (pp == NULL || result != SSH_HWACCEL_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Hardware acceleration dropped packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_HWACCELDROP);

      if (pp)
        ssh_interceptor_packet_free(pp);

      goto error;
    }

  pc->pp = pp;

  /* If using 64 bit sequence numbers, remove the most significant
     32 bits of the sequence number that was previously inserted to
     the packet. */
  if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
    {
      if (!fastpath_transform_out_delete_seq_high(tc, pc))
        goto error;
    }

  fastpath_transform_out_finish(pc->engine->fastpath, tc, pc);
  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(pc->engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
}

#endif /* SSHDIST_IPSEC_HWACCEL */


/************** Software auth cipher outbound transform handler **************/

/* Perform software encryption and MAC computation when combined mode
   algorithm is selected. */
static void
fastpath_transform_out_sw_combined(SshFastpath fastpath,
                                   SshFastpathTransformContext tc,
                                   SshEnginePacketContext pc,
                                   size_t enc_ofs, size_t enc_len)
{
  SSH_INTERCEPTOR_STACK_MARK();

  /* This handler is for software auth ciphers only. */
  SSH_ASSERT(tc->with_sw_cipher);
  SSH_ASSERT(tc->with_sw_auth_cipher);
  SSH_ASSERT(!tc->with_sw_mac);
  SSH_ASSERT(tc->mac_accel == NULL);
  SSH_ASSERT(tc->enc_accel == NULL);
  SSH_ASSERT(tc->encmac_accel == NULL);
  SSH_ASSERT(tc->transform_accel == NULL);

  /* Update packet context information before icv computation. */
  fastpath_transform_out_update_pc(tc, pc);

  /* Set outer header df-bit on IPv4 packets. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP4
      && pc->u.flow.trr->df_bit_processing != SSH_ENGINE_DF_KEEP)
    {
      if (!fastpath_transform_process_df(pc))
        goto error;
    }

  /* Perform encryption in software. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      /* Encrypt the packet ans compute ICV. */
      if (ssh_fastpath_esp_transform_combined_out(tc, pc, enc_ofs, enc_len,
                                                  pc->u.flow.mac_icv_ofs)
          == FALSE)
        {
          goto error;
        }
    }

#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      /* Compute ICV for AH. */
      if (ssh_fastpath_ah_compute_icv(tc, pc, -tc->natt_len,
                                      pc->u.flow.mac_ofs, pc->u.flow.mac_len,
                                      pc->u.flow.mac_icv_ofs)
          == FALSE)
        {
          goto error;
        }
    }
#endif /* SSH_IPSEC_AH */

  fastpath_transform_out_finish(fastpath, tc, pc);
  return;

 error:

  pc->pp = NULL;
  fastpath_transform_out_fail(pc->engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
}


/********************** Software outbound transform handler ******************/

/* Perform software encryption. */
static void
fastpath_transform_out_sw_enc(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc,
                              size_t enc_ofs, size_t enc_len)
{
  SSH_INTERCEPTOR_STACK_MARK();

  /* This handler is for software ciphers only. */
  SSH_ASSERT(tc->with_sw_cipher);
  SSH_ASSERT(!tc->with_sw_auth_cipher);
  SSH_ASSERT(tc->enc_accel == NULL);
  SSH_ASSERT(tc->encmac_accel == NULL);
  SSH_ASSERT(tc->transform_accel == NULL);

  /* Perform encryption in software. */
  if (pc->transform & SSH_PM_IPSEC_ESP)
    {
      /* Encrypt the packet.  We also encrypt the iv. */
      if (ssh_fastpath_esp_transform_out(tc, pc, enc_ofs, enc_len) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("esp_transform failed"));
          goto error;
        }
    }

  fastpath_transform_out_start_mac(fastpath, tc, pc);
  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
}

/* Perform software MAC computation. */
static void
fastpath_transform_out_sw_mac(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc)
{
  Boolean ok;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(tc->with_sw_mac);

#ifdef SSH_IPSEC_AH
  if (pc->transform & SSH_PM_IPSEC_AH)
    {
      /* Compute ICV for AH. */
      ok = ssh_fastpath_ah_compute_icv(tc, pc, -tc->natt_len,
                                       pc->u.flow.mac_ofs, pc->u.flow.mac_len,
                                       pc->u.flow.mac_icv_ofs);
    }
  else
#endif /* SSH_IPSEC_AH */
    {
      /* Compute ICV for ESP. */
      ok = ssh_fastpath_esp_compute_icv(tc, pc, pc->u.flow.mac_ofs,
                                        pc->u.flow.mac_len,
                                        pc->u.flow.mac_icv_ofs);
    }

  if (ok == TRUE)
    {
      fastpath_transform_out_finish(fastpath, tc, pc);
    }
  else
    {
      pc->pp = NULL;
      fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
    }
}

/* Performs the last step of outbound IPsec transform. This function computes
   MAC in software and completes the packet processing, or computes the MAC
   in hardware. */
static void
fastpath_transform_out_start_mac(SshFastpath fastpath,
                                 SshFastpathTransformContext tc,
                                 SshEnginePacketContext pc)
{
  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_LOWOK, ("transform complete, pp=0x%p", pc->pp));

  /* We must have a packet here. Otherwise a fatal error. */
  SSH_ASSERT(pc->pp != NULL);

  /* Update packet context information after tunneling. */
  fastpath_transform_out_update_pc(tc, pc);

  /* Set outer header df-bit on IPv4 packets. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP4
      && pc->u.flow.trr->df_bit_processing != SSH_ENGINE_DF_KEEP)
    {
      if (!fastpath_transform_process_df(pc))
        goto error;
    }

#ifdef SSHDIST_IPSEC_HWACCEL
  /* Compute MAC in hardware. */
  if (tc->mac_accel)
    {
      /* If using 64 bit sequence numbers, insert the most significant
         32 bits of the sequence number to the packet. The data gets
         removed in fastpath_transform_out_finish_hw_mac. */
      if (pc->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          if (!fastpath_transform_out_append_seq_high(pc))
            goto error;
        }

      /* Use hardware acceleration to perform the MAC . */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing hardware MAC"));

      ssh_hwaccel_perform_ipsec(pc->u.flow.tc->mac_accel, pc->pp, 0, 0,
                                pc->u.flow.mac_ofs,
                                pc->u.flow.mac_len,
                                pc->u.flow.mac_icv_ofs,
                                fastpath_transform_out_finish_hw_mac,
                                (void *)pc);
      return;
    }
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Compute MAC in software. */
  if (tc->with_sw_mac)
    {
      fastpath_transform_out_sw_mac(fastpath, tc, pc);
      return;
    }

  fastpath_transform_out_finish(fastpath, tc, pc);
  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
}

/* Performs the last step of outbound IPsec transform. */
static void
fastpath_transform_out_finish(SshFastpath fastpath,
                              SshFastpathTransformContext tc,
                              SshEnginePacketContext pc)
{
  SSH_INTERCEPTOR_STACK_MARK();































#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (pc->transform & SSH_PM_IPSEC_NATT)
    {
      if (!fastpath_transform_calc_natt_udp_header_checksum(tc, pc))
        goto error;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  SSH_DUMP_PACKET(SSH_D_PCKDMP, "Cryptotext:", pc->pp);

  /* Indicate successful completion of the transform. */
  ssh_fastpath_release_transform_context(fastpath, tc);
  (*pc->u.flow.tr_callback)(pc, SSH_ENGINE_RET_OK, pc->u.flow.tr_context);

  return;

 error:
  pc->pp = NULL;
  fastpath_transform_out_fail(fastpath, pc, SSH_ENGINE_RET_ERROR);
}
