/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code for flow id computations in the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFlowId"


/* Computes the flow id for a TCP or UDP session.  This can be used to
   compute the flow id when it uses IP addresses or port numbers that
   are different from those found in the packet (as is the case when
   NAT is being performed). */
Boolean
ssh_engine_compute_tcpudp_flowid(SshEngine engine,
                                 SshUInt8 ipproto,
                                 SshUInt32 tunnel_id,
                                 const SshIpAddr src,
                                 const SshIpAddr dst,
                                 SshUInt16 src_port,
                                 SshUInt16 dst_port,
                                 const SshUInt32 *extension,
                                 unsigned char *flow_id,
                                 Boolean from_adapter)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  Boolean is_ip6, is_ok;
  size_t len;

  if (SSH_IP_IS6(src) || SSH_IP_IS6(dst))
    is_ip6 = TRUE;
  else
    is_ip6 = FALSE;

  len = (is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN) + SSH_TCPH_HDRLEN;

  /* Allocate a dummy packet for flow id computation */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    from_adapter ?
                                    SSH_PACKET_FROMADAPTER :
                                    SSH_PACKET_FROMPROTOCOL,
                                    is_ip6 ?
                                    SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    len);

  if (!pp)
    return FALSE;
  ucp = ssh_interceptor_packet_pullup(pp, len);
  if (!ucp)
    return FALSE;

  memset(ucp, 0, len);
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(pp->extension, extension, sizeof(pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (is_ip6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(src, ucp);
      SSH_IPH6_SET_DST(dst, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      /* The ports are at the same offsets for TCP and UDP */
      SSH_TCPH_SET_SRCPORT(ucp + SSH_IPH6_HDRLEN, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + SSH_IPH6_HDRLEN, dst_port);
    }
  else
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, len);
      SSH_IPH4_SET_SRC(src, ucp);
      SSH_IPH4_SET_DST(dst, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      /* The ports are at the same offsets for TCP and UDP */
      SSH_TCPH_SET_SRCPORT(ucp + SSH_IPH4_HDRLEN, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + SSH_IPH4_HDRLEN, dst_port);
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for flow ID"), pp);

  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }
  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, tunnel_id,
                                     SSH_IPSEC_INVALID_INDEX))
    {
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;

      ssh_engine_free_pc(engine, pc);
      return FALSE;
    }

  is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp, tunnel_id,
                                  flow_id);

  ssh_engine_free_pc(engine, pc);

  if (is_ok)
    ssh_interceptor_packet_free(pp);
  return is_ok;
}

/* Computes a flow id for incoming traffic according to the given
   transform.  This determines the outermost SPI for such traffic, and
   generates a flow id that will match with such incoming traffic.
   The generated flow id will be stored in `flow_id'. */

Boolean ssh_engine_compute_transform_flowid(SshEngine engine,
                                            SshEngineTransformData trd,
                                            SshIpAddr own_addr,
                                            SshUInt32 outer_tunnel_id,
                                            Boolean use_old_spis,
                                            unsigned char *flow_id)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  SshPmTransform transform;
  SshUInt32 spi;
  SshUInt8 ipproto = 0;
  Boolean is_ip6, is_ok, spi_zero;
  size_t ofs, len;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  is_ip6 = SSH_IP_IS6(own_addr);
  len = is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN;
  spi_zero = FALSE;
  transform = trd->transform;

  if (transform & SSH_PM_IPSEC_AH)
    {
      ipproto = SSH_IPPROTO_AH;
      len += 12;
    }
  else if (transform & SSH_PM_IPSEC_ESP)
    {
      ipproto = SSH_IPPROTO_ESP;
      len += 8;
    }
#ifdef SSHDIST_L2TP
  else if (transform & SSH_PM_IPSEC_L2TP)
    {
      ipproto = SSH_IPPROTO_UDP;
      len += 8;
    }
#endif /* SSHDIST_L2TP */
  else
    ssh_fatal("ssh_engine_compute_transform_flowid: bad tr 0x%08lx",
              (unsigned long) transform);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    {
      /* ipproto gets overwritten from the previous value as the NAT-T header
         is the outermost header. */
      ipproto = SSH_IPPROTO_UDP;
      len += 8;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Allocate a dummy packet for flow id computation */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    SSH_PACKET_FROMADAPTER,
                                    is_ip6 ?
                                    SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    len);

  if (!pp)
    return FALSE;
  ucp = ssh_interceptor_packet_pullup(pp, len);
  if (!ucp)
    return FALSE;
  memset(ucp, 0, len);

  if (is_ip6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(&trd->gw_addr, ucp);
      SSH_IPH6_SET_DST(own_addr, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      ofs = SSH_IPH6_HDRLEN;
    }
  else
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, len);
      SSH_IPH4_SET_SRC(&trd->gw_addr, ucp);
      SSH_IPH4_SET_DST(own_addr, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      ofs = SSH_IPH4_HDRLEN;
    }

  /* Set the SPI value that will appear in incoming packets. */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (transform & SSH_PM_IPSEC_NATT)
    {
      SSH_UDPH_SET_SRCPORT(ucp + ofs, trd->remote_port);
      SSH_UDPH_SET_DSTPORT(ucp + ofs, trd->local_port);
      ofs += 8;

      /* Store also the SPI to the ESP header so we can multiplex different
         SAs between two hosts using NAT-T. */
      SSH_ASSERT((transform & SSH_PM_IPSEC_AH) == 0);
      SSH_ASSERT(transform & SSH_PM_IPSEC_ESP);

      spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_ESP_IN] :
        trd->spis[SSH_PME_SPI_ESP_IN];

      if (!spi)
        spi_zero = TRUE;

      SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, spi);
    }
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    {
      if (transform & SSH_PM_IPSEC_AH)
        {
          spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_AH_IN] :
            trd->spis[SSH_PME_SPI_AH_IN];

          if (!spi)
            spi_zero = TRUE;
          SSH_PUT_32BIT(ucp + ofs + SSH_AHH_OFS_SPI, spi);
        }
      else
        if (transform & SSH_PM_IPSEC_ESP)
          {
            spi = use_old_spis ? trd->old_spis[SSH_PME_SPI_ESP_IN] :
              trd->spis[SSH_PME_SPI_ESP_IN];

            if (!spi)
              spi_zero = TRUE;

            SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, spi);
          }
#ifdef SSHDIST_L2TP
        else
          if (transform & SSH_PM_IPSEC_L2TP)
            {
              SSH_UDPH_SET_SRCPORT(ucp + ofs, trd->l2tp_remote_port);
              SSH_UDPH_SET_DSTPORT(ucp + ofs, trd->l2tp_local_port);
            }
#endif /* SSHDIST_L2TP */
          else
            ssh_fatal("ssh_engine_compute_transform_flowid: bad tr 0x%08lx",
                      (unsigned long) transform);
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for transform flow ID "
                             "computation"), pp);

  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }
  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, outer_tunnel_id,
                                     SSH_IPSEC_INVALID_INDEX))
    {
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;

      ssh_engine_free_pc(engine, pc);
      return FALSE;
    }

  if (spi_zero == TRUE)
    {
      /* No valid SPI is defined. Leave flow id as zero.  */
      memset(flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
      is_ok = TRUE;
    }
  else
    {
      is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp,
                                      outer_tunnel_id, flow_id);
    }

  ssh_engine_free_pc(engine, pc);

  if (is_ok)
    ssh_interceptor_packet_free(pp);
  return is_ok;
}

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
                                          unsigned char *flow_id)
{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp;
  unsigned char *ucp;
  SshEngineFlowControl c_flow;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEnginePolicyRule rule;
  Boolean forward_local, reverse_local, ret;
  SshIpAddr src_ip, dst_ip;
  SshUInt16 src_port, dst_port;
  unsigned char icmp_identifier[2] = {0};
  SshUInt32 tunnel_id;
  Boolean from_adapter;
  Boolean is_ip6, is_ok;
  size_t ofs, len;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshEngineNextHopData nh;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);

  rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
  SSH_ASSERT(rule != NULL);

  memset(flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
  ret = TRUE;

  if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
    {
      SshIpAddrStruct dst_ip_struct;

      if (d_flow->forward_transform_index != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd = SSH_ENGINE_GET_TRD(engine,
                                     d_flow->forward_transform_index);
          if (c_trd == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Unable to re-compute ipsec incoming "
                         "flow id: transform invalidated."));
              return FALSE;
            }
          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                             d_flow->forward_transform_index);

          dst_ip_struct = d_trd->own_addr;

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
          if (rule->flags & SSH_ENGINE_RULE_SCTP_MULTIHOME)
            {
              if (rule->protocol == SSH_PROTOCOL_IP4)
                SSH_IP_DECODE(&dst_ip_struct, rule->src_ip_low, 4);
              else
                SSH_IP_DECODE(&dst_ip_struct, rule->src_ip_low, 16);
            }
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

          /* If is_forward == FALSE compute flow-id for freshest SPI.
             If is_forward == TRUE compute flow-id for pre-rekey SPI. */
#ifdef SSH_IPSEC_MULTICAST
          /* For transforms having multicast gw IP, multicast gw IP
           * should be used to calculate flow id. */
          if (SSH_IP_IS_MULTICAST(&(d_trd->gw_addr)))
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Transform has multicast peer IP, thus using"
                         " multicast peer IP for flow id calculations."));
              ret = ssh_engine_compute_transform_flowid(engine, d_trd,
                                                        &(d_trd->gw_addr),
                                                        c_trd->outer_tunnel_id,
                                                        is_forward, flow_id);
            }
          else
#endif /* SSH_IPSEC_MULTICAST */
            ret = ssh_engine_compute_transform_flowid(engine, d_trd,
                                                      &dst_ip_struct,
                                                      c_trd->outer_tunnel_id,
                                                      is_forward, flow_id);

          FASTPATH_RELEASE_TRD(engine->fastpath,
                               d_flow->forward_transform_index);
        }
      return ret;
    }
  else
    {
      reverse_local = forward_local = FALSE;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (d_flow->reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          nh = FASTPATH_GET_NH(engine->fastpath, d_flow->reverse_nh_index);
          if (nh->flags & SSH_ENGINE_NH_LOCAL)
            reverse_local = TRUE;
          FASTPATH_RELEASE_NH(engine->fastpath, d_flow->reverse_nh_index);
        }

      if (d_flow->forward_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          nh = FASTPATH_GET_NH(engine->fastpath, d_flow->forward_nh_index);
          if (nh->flags & SSH_ENGINE_NH_LOCAL)
            forward_local = TRUE;
          FASTPATH_RELEASE_NH(engine->fastpath, d_flow->forward_nh_index);
        }
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      forward_local = d_flow->forward_local;
      reverse_local = d_flow->reverse_local;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      if (is_forward)
        from_adapter = reverse_local ? FALSE : TRUE;
      else
        from_adapter = forward_local ? FALSE : TRUE;

      tunnel_id = 0;
      if (is_forward == TRUE)
        {
          /* Only assume tunnels for non-"magic unroutable" endpoints.
             Using the rule->tunnel_id assures that we also get
             'magic' system internal tunnel id's correct. */
          if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I)
            tunnel_id = rule->tunnel_id;
        }
      else if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R)
        {
          /* is_forward == FALSE */
          if (d_flow->forward_transform_index != SSH_IPSEC_INVALID_INDEX)
            {
              c_trd = SSH_ENGINE_GET_TRD(engine,
                                         d_flow->forward_transform_index);
              if (c_trd == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Unable to resolve transform of flow"));
                  return FALSE;
                }
              d_trd =
                FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                           d_flow->forward_transform_index);

              /* Note that this will work incorrectly, if
                 'magic' tunnel id 1 packets are involved. */
              tunnel_id = d_trd->inbound_tunnel_id;
              FASTPATH_RELEASE_TRD(engine->fastpath,
                                   d_flow->forward_transform_index);
            }
        }

      /* Select and encode IP addresses and ports */
      if (is_forward)
        {
          src_port = d_flow->src_port;
          dst_port = d_flow->dst_port;
          src_ip = &d_flow->src_ip;
          dst_ip = &d_flow->dst_ip;
        }
      else
        {
#ifdef SSHDIST_IPSEC_NAT
          src_ip = &d_flow->nat_dst_ip;
          dst_ip = &d_flow->nat_src_ip;
          src_port = d_flow->nat_dst_port;
          dst_port = d_flow->nat_src_port;
#else /* SSHDIST_IPSEC_NAT */
          src_ip = &d_flow->dst_ip;
          dst_ip = &d_flow->src_ip;
          src_port = d_flow->dst_port;
          dst_port = d_flow->src_port;
#endif /* SSHDIST_IPSEC_NAT */
        }

      if (SSH_IP_IS6(src_ip) || SSH_IP_IS6(dst_ip))
        is_ip6 = TRUE;
      else
        is_ip6 = FALSE;

      /* For ICMP flows extract the Identifier from the flow */
      if (d_flow->ipproto == SSH_IPPROTO_ICMP
          || d_flow->ipproto == SSH_IPPROTO_IPV6ICMP)
        {
#ifdef SSHDIST_IPSEC_NAT
          /* ICMP identifier is stored in nat_src */
          if (is_forward)
            {
              icmp_identifier[0] = (d_flow->src_port >> 8) & 0xff;
              icmp_identifier[1] = (d_flow->src_port & 0xff);
            }
          else
            {
              icmp_identifier[0] = (d_flow->nat_src_port >> 8) & 0xff;
              icmp_identifier[1] = (d_flow->nat_src_port & 0xff);

            }
#else /* SSHDIST_IPSEC_NAT */
          icmp_identifier[0] = (d_flow->src_port >> 8) & 0xff;
          icmp_identifier[1] = (d_flow->src_port & 0xff);
#endif /* SSHDIST_IPSEC_NAT */
        }

      /* Allocate 20 bytes to contain the upper layer protocol headers.
         The maximum required is for TCP packets. */
      len = (is_ip6 ? SSH_IPH6_HDRLEN : SSH_IPH4_HDRLEN) + SSH_TCPH_HDRLEN;

      /* Allocate a dummy packet for flow id computation */
      pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                        from_adapter ?
                                        SSH_PACKET_FROMADAPTER :
                                        SSH_PACKET_FROMPROTOCOL,
                                        is_ip6 ?
                                        SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                        SSH_INTERCEPTOR_INVALID_IFNUM,
                                        SSH_INTERCEPTOR_INVALID_IFNUM,
                                        len);

      if (!pp)
        return FALSE;
      ucp = ssh_interceptor_packet_pullup(pp, len);
      if (!ucp)
        return FALSE;
      memset(ucp, 0, len);

      if (is_ip6)
        {
          SSH_IPH6_SET_VERSION(ucp, 6);
          SSH_IPH6_SET_LEN(ucp, len - SSH_IPH6_HDRLEN);
          SSH_IPH6_SET_SRC(src_ip, ucp);
          SSH_IPH6_SET_DST(dst_ip, ucp);
          SSH_IPH6_SET_NH(ucp, d_flow->ipproto);
          ofs = SSH_IPH6_HDRLEN;
        }
      else
        {
          SSH_IPH4_SET_VERSION(ucp, 4);
          SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
          SSH_IPH4_SET_LEN(ucp, len);
          SSH_IPH4_SET_SRC(src_ip, ucp);
          SSH_IPH4_SET_DST(dst_ip, ucp);
          SSH_IPH4_SET_PROTO(ucp, d_flow->ipproto);
          ofs = SSH_IPH4_HDRLEN;
        }

      switch (d_flow->ipproto)
        {
        case SSH_IPPROTO_TCP:
          SSH_TCPH_SET_SRCPORT(ucp + ofs, src_port);
          SSH_TCPH_SET_DSTPORT(ucp + ofs, dst_port);
          break;

        case SSH_IPPROTO_UDP:
        case SSH_IPPROTO_UDPLITE:
          SSH_UDPH_SET_SRCPORT(ucp + ofs, src_port);
          SSH_UDPH_SET_DSTPORT(ucp + ofs, dst_port);

          /* For DHCP flows set the Transaction ID from protocol_xid . */
          if (dst_port == 67 || dst_port == 68 || dst_port == 546 ||
              dst_port == 547)
            SSH_PUT_32BIT(ucp + ofs + 12, d_flow->protocol_xid);
          break;

        case SSH_IPPROTO_SCTP:
          SSH_SCTPH_SET_SRCPORT(ucp + ofs, src_port);
          SSH_SCTPH_SET_DSTPORT(ucp + ofs, dst_port);
          break;

        case SSH_IPPROTO_ICMP:
          SSH_ICMPH_SET_TYPE(ucp + ofs, (d_flow->dst_port >> 8));
          SSH_ICMPH_SET_CODE(ucp + ofs, (d_flow->dst_port & 0xff));

          ofs += 4;
          SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
          SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
          break;

        case SSH_IPPROTO_IPV6ICMP:
          SSH_ICMP6H_SET_TYPE(ucp + ofs, (d_flow->dst_port >> 8));
          SSH_ICMP6H_SET_CODE(ucp + ofs, (d_flow->dst_port & 0xff));

          ofs += 4;
          SSH_PUT_8BIT(ucp + ofs, icmp_identifier[0]);
          SSH_PUT_8BIT(ucp + ofs + 1, icmp_identifier[1]);
          break;

        case SSH_IPPROTO_ESP:
          SSH_PUT_32BIT(ucp + ofs + SSH_ESPH_OFS_SPI, d_flow->protocol_xid);
          break;

        case SSH_IPPROTO_AH:
          SSH_PUT_32BIT(ucp + ofs + SSH_AHH_OFS_SPI, d_flow->protocol_xid);
          break;
        }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
      memcpy(pp->extension, d_flow->extension, sizeof(pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

      SSH_DUMP_PACKET(SSH_D_MY, ("Constructed packet for flow ID from flow "
                                 "computation"), pp);

      pc = ssh_engine_alloc_pc(engine);
      if (pc == NULL)
        {
          ssh_interceptor_packet_free(pp);
          return FALSE;
        }
      if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, tunnel_id,
                                         SSH_IPSEC_INVALID_INDEX))
        {
          if (pc->pp != NULL)
            ssh_interceptor_packet_free(pc->pp);
          pc->pp = NULL;

          ssh_engine_free_pc(engine, pc);
          return FALSE;
        }

      /* If this is not an incoming IPsec flow then clear the PC_IS_IPSEC
         flag of pc. This is required for correct flow id computation of
         IPsec packets which should not be decapsulated by this implemetation
         (i.e. IPsec packets not directed to this host or directed to a
         coexisting IPsec stack on this host.) */
      if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING))
        pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

      is_ok = (*engine->flow_id_hash)(engine->fastpath, pc, pp, tunnel_id,
                                      flow_id);

      ssh_engine_free_pc(engine, pc);

      if (is_ok)
        ssh_interceptor_packet_free(pp);
      return is_ok;
    }
}


SshInterceptorPacket
ssh_engine_icmp_get_inner_packet(SshEngine engine, SshInterceptorPacket pp)

{
  SshEnginePacketContext pc;
  SshInterceptorPacket pp_ret;
  size_t ip_len;
  size_t inner_hdrlen, offset;
  size_t constructed_packet_len = 0;
  unsigned char *ucp;
  SshIpAddrStruct src, dst;
  SshUInt16 src_port = 0, dst_port = 0;
  unsigned char payload[8];
  size_t payload_len = 0;
  SshUInt32 spi = 0;
  SshInetIPProtocolID ipproto = 0;
  SshUInt8 icmp_type = 0, icmp_code = 0;
  SshUInt32 constructed_packet_flags;
  SshInterceptorProtocol constructed_packet_protocol
    = SSH_PROTOCOL_NUM_PROTOCOLS;
  int i;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  Boolean is_ike_natt = FALSE;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, 0,
                                     SSH_IPSEC_INVALID_INDEX))
    goto drop;

  if (pc->ipproto != SSH_IPPROTO_ICMP
#if defined (WITH_IPV6)
      && pc->ipproto != SSH_IPPROTO_IPV6ICMP
#endif /* WITH_IPV6 */
      )
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet not ICMP, dropping"));
      goto drop;
    }

  ip_len = pc->packet_len;

  /* Process the ICMP according to its type. */
  if (pc->ipproto == SSH_IPPROTO_ICMP)
    {
      /* Buffer space for copying inner IPv4 header, atleast 8 bytes
         of inner packet payload and optionally 4 bytes of XID. */
      unsigned char header[SSH_IPH4_HDRLEN];

      if (pc->icmp_type != SSH_ICMP_TYPE_UNREACH &&
          pc->icmp_type != SSH_ICMP_TYPE_SOURCEQUENCH &&
          pc->icmp_type != SSH_ICMP_TYPE_TIMXCEED &&
          pc->icmp_type != SSH_ICMP_TYPE_PARAMPROB)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Packet not an ICMP error message, dropping"));
          goto drop;
        }

      constructed_packet_protocol = SSH_PROTOCOL_IP4;

      /* Check for truncated ICMPv4 packet. Must have at least
         an IPv4 header inside. */
      if (ip_len < pc->hdrlen + SSH_ICMPH_UNREACH_LEN + SSH_IPH4_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("ICMP; truncated error"));
          goto drop;
        }
      offset = pc->hdrlen + SSH_ICMPH_UNREACH_LEN;

      /* Copy out the offending IPv4 header without options to
         check for header length and inner protocol. */
      ssh_interceptor_packet_copyout(pc->pp, offset, header, SSH_IPH4_HDRLEN);

      /* Check inner IPv4 header IP version. */
      if (SSH_IPH4_VERSION(header) != 4)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("ICMP; Bad offending IP header version %d",
                     (int) SSH_IPH4_VERSION(header)));
          goto drop;
        }

      /* Get and check the inner IPv4 header length. Needs to be
         at least std header and not beyond packet boundary. */
      inner_hdrlen = 4 * SSH_IPH4_HLEN(header);
      if (inner_hdrlen < SSH_IPH4_HDRLEN
          || ip_len < offset + inner_hdrlen)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("ICMP; Bad offending IP header length %d",
                     (int) inner_hdrlen));
          goto drop;
        }

      /* Take src and dst IP, and ipproto. Note that the ICMP packet is
         going in the direction OPPOSITE to the original packet, and will
         get routed to the SOURCE of the original packet. Consequently,
         normal and reverse directions must be REVERSED for ICMP errors
         to get correct routing information for the packets. */
      SSH_IPH4_SRC(&dst, header);
      SSH_IPH4_DST(&src, header);
      ipproto = SSH_IPH4_PROTO(header);

      /* Compute the length of the constructed packet. */
      constructed_packet_len = SSH_IPH4_HDRLEN;

      /* Then take src,dst port from original (inner) packet that
         triggered the ICMP. Require the minimum amount of transport
         header data. */
      offset += inner_hdrlen;
      switch (ipproto)
        {
        case SSH_IPPROTO_TCP:
          if (ip_len < offset + 4)
            goto drop;

          /* Constructed packet has a complete TCP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_TCPH_DSTPORT(payload);
          dst_port = SSH_TCPH_SRCPORT(payload);
          constructed_packet_len += SSH_TCPH_HDRLEN;
          break;

        case SSH_IPPROTO_UDP:
          if (ip_len < offset + 4)
            goto drop;

          /* Constructed packet has a complete UDP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_UDPH_DSTPORT(payload);
          dst_port = SSH_UDPH_SRCPORT(payload);
          constructed_packet_len += SSH_UDPH_HDRLEN;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          /* Check if violating packet is UDP NAT-T. */
          for (i = 0; i < engine->num_ike_ports; i++)
            {
              if (((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
                   dst_port == engine->local_ike_natt_ports[i]) ||
                  ((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
                   dst_port == engine->remote_ike_natt_ports[i]))
                {
                  is_ike_natt = TRUE;
                  break;
                }
            }

          if (is_ike_natt
              && ip_len >= (offset + SSH_UDPH_HDRLEN + SSH_ESPH_OFS_SPI + 4))
            {
              /* Copy from the SPI data to payload buf and parse the value. */
              ssh_interceptor_packet_copyout(pc->pp,
                                             offset + SSH_UDPH_HDRLEN
                                             + SSH_ESPH_OFS_SPI,
                                             payload, 4);

              /* Add SPI value after UDP header in the constructed packet. */
              spi = SSH_GET_32BIT(payload);
              constructed_packet_len += 4;
            }
          else
            {
              is_ike_natt = FALSE;
            }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          break;

        case SSH_IPPROTO_UDPLITE:
          if (ip_len < offset + 4)
            goto drop;

          /* Constructed packet has a complete UDPLITE header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_UDPH_DSTPORT(payload);
          dst_port = SSH_UDPH_SRCPORT(payload);
          constructed_packet_len += SSH_UDPH_HDRLEN;
          break;

        case SSH_IPPROTO_SCTP:
          if (ip_len < offset + 4)
            goto drop;

          /* Constructed packet has a complete SCTP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_SCTPH_DSTPORT(payload);
          dst_port = SSH_SCTPH_SRCPORT(payload);
          constructed_packet_len += SSH_SCTPH_HDRLEN;
          break;

        case SSH_IPPROTO_AH:
          if (ip_len < offset + SSH_AHH_OFS_SPI + 4)
            goto drop;

          /* Constructed packet has a complete AH header but only
             SPI value is filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset + SSH_AHH_OFS_SPI,
                                         payload, 4);
          spi = SSH_GET_32BIT(payload);
          constructed_packet_len += SSH_AHH_MINHDRLEN;
          break;

        case SSH_IPPROTO_ESP:
          if (ip_len < offset + SSH_ESPH_OFS_SPI + 4)
            goto drop;

          /* Constructed packet has a complete ESP header but only
             SPI value is filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset + SSH_ESPH_OFS_SPI,
                                         payload, 4);
          spi = SSH_GET_32BIT(payload);
          constructed_packet_len += SSH_ESPH_HDRLEN;
          break;

        case SSH_IPPROTO_ICMP:
          if (ip_len < offset + 4)
            goto drop;

          /* Constructed packet has eight bytes of ICMP header but only
             type, code and identifier (for echo) values are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          icmp_type = SSH_ICMPH_TYPE(payload);
          icmp_code = SSH_ICMPH_CODE(payload);
          constructed_packet_len += SSH_ICMP_MINLEN;

          /* Leave icmp identifier to payload buf. */
          if (icmp_type == SSH_ICMP_TYPE_ECHO ||
              icmp_type == SSH_ICMP_TYPE_ECHOREPLY)
            {
              if (ip_len < offset + 6)
                goto drop;
              ssh_interceptor_packet_copyout(pc->pp, offset + 4, payload, 2);
              payload_len = 2;
            }
          break;

        default:
          /* Copy up to 8 bytes of payload for other protocols. */
          payload_len = 8;
          if (offset + payload_len > ip_len)
            payload_len = ip_len - offset;
          if (payload_len > 0)
            ssh_interceptor_packet_copyout(pc->pp, offset, payload,
                                           payload_len);
          constructed_packet_len += payload_len;
          break;
        }
    }
#if defined (WITH_IPV6)
  else if (pc->ipproto == SSH_IPPROTO_IPV6ICMP)
    {
      unsigned char header[SSH_IPH6_HDRLEN];
      unsigned char src_buf[16];
      SshUInt32 x, ext_hdr_len;

      if (pc->icmp_type != SSH_ICMP6_TYPE_UNREACH &&
          pc->icmp_type != SSH_ICMP6_TYPE_TOOBIG &&
          pc->icmp_type != SSH_ICMP6_TYPE_TIMXCEED &&
          pc->icmp_type != SSH_ICMP6_TYPE_PARAMPROB)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Packet not an ICMP error message, dropping"));
          goto drop;
        }

      constructed_packet_protocol = SSH_PROTOCOL_IP6;

      /* Check packet length and copy out inner IPv6 header. */
      offset = pc->hdrlen + SSH_ICMP6H_TOOBIG_LEN;
      if (offset + SSH_IPH6_HDRLEN >= ip_len)
        goto drop;
      ssh_interceptor_packet_copyout(pp, offset, header, SSH_IPH6_HDRLEN);

      /* Check inner IPv6 header IP version. */
      if (SSH_IPH6_VERSION(header) != 6)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("ICMP; Bad offending IPv6 header version %d",
                     (int) SSH_IPH6_VERSION(header)));
          goto drop;
        }

      /* Parse src and dst IP, and ipproto, See comments for the IPv4
         case for the logic behin these. */
      SSH_IPH6_SRC(&dst, header);
      SSH_IPH6_DST(&src, header);

      ipproto = SSH_IPH6_NH(header);
      offset += SSH_IPH6_HDRLEN;

      /* Compute the length of the constructed packet. */
      constructed_packet_len = SSH_IPH6_HDRLEN;

      /* The following part iterates through extension headers
         to find out ipproto and possibly port numbers.  If the
         packet is too short to contain the offending packet's
         payload so that it can be meaningfully parsed, then
         drop the packet. Note that this reuses the header buf
         for extension headers. */
    next_header:
      switch (ipproto)
        {
        case 0:
          /* Hop-by-hop header is not copied to the contructed packet.
             Sanity check extension header length and skip to next header. */
          if (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN >= ip_len)
            goto drop;
          ssh_interceptor_packet_copyout(pp, offset, header,
                                         SSH_IP6_EXT_HOP_BY_HOP_HDRLEN);
          ipproto = SSH_IP6_EXT_COMMON_NH(header);
          offset += SSH_IP6_EXT_COMMON_LENB(header);
          goto next_header;
          break;

        case SSH_IPPROTO_IPV6ROUTE:
          /* Routing header is not copied to the contructed packet.
             Sanity check extension header length and skip to next header. */
          if (offset + SSH_IP6_EXT_ROUTING_HDRLEN >= ip_len)
            goto drop;
          ssh_interceptor_packet_copyout(pc->pp, offset, header,
                                         SSH_IP6_EXT_ROUTING_HDRLEN);
          if (SSH_IP6_EXT_ROUTING_TYPE(header) != 0)
            goto drop;
          ipproto = SSH_IP6_EXT_ROUTING_NH(header);
          x = SSH_IP6_EXT_ROUTING_LEN(header);

          /* Extension header length must be multiple of 16 octets
             (length of IPv6 address). */
          if (x & 0x1)
            goto drop;
          ext_hdr_len = 8 + 8 * x;
          if (x != 0)
            {
              SshUInt32 n_addrs = x >> 1;
              SshUInt32 n_segs = SSH_IP6_EXT_ROUTING_SEGMENTS(header);

              if (n_segs > n_addrs)
                goto drop;

              if (offset + 8 + n_addrs * 16 > ip_len)
                goto drop;
              ssh_interceptor_packet_copyout(pp,
                                             offset + n_addrs * 16 - 8,
                                             src_buf, 16);
              SSH_IP_DECODE(&src, src_buf, 16);
            }
          offset += ext_hdr_len;
          goto next_header;
          break;

        case SSH_IPPROTO_IPV6OPTS:
          /* Destination options header is not copied to the constructed
             packet. Sanity check extension header length and skip to
             next header. */
          if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > ip_len)
            goto drop;
          ssh_interceptor_packet_copyout(pc->pp, offset, header,
                                         SSH_IP6_EXT_DSTOPTS_HDRLEN);
          offset += SSH_IP6_EXT_DSTOPTS_LENB(header);
          ipproto = SSH_IP6_EXT_DSTOPTS_NH(header);
          goto next_header;
          break;

        case SSH_IPPROTO_IPV6FRAG:
          /* Fragment header is not copied to the constructed packet.
             Sanity check extension header length and skip to next header. */
          if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > ip_len)
            goto drop;
          ssh_interceptor_packet_copyout(pc->pp, offset, header,
                                         SSH_IP6_EXT_FRAGMENT_HDRLEN);
          /* Drop non-first fragments, since we can't find their
             flow since we don't know their ipproto and ports. */
          if (SSH_IP6_EXT_FRAGMENT_OFFSET(header) != 0)
            goto drop;
          offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
          ipproto = SSH_IP6_EXT_FRAGMENT_NH(header);
          goto next_header;
          break;

          /* Dig out the port numbers of TCP, UDP and SCTP packets.
             Require the minimum amount of transport header data. */
        case SSH_IPPROTO_TCP:
          if (offset + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete TCP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_TCPH_DSTPORT(payload);
          dst_port = SSH_TCPH_SRCPORT(payload);
          constructed_packet_len += SSH_TCPH_HDRLEN;
          break;

        case SSH_IPPROTO_UDP:
          if (offset + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete UDP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_UDPH_DSTPORT(payload);
          dst_port = SSH_UDPH_SRCPORT(payload);
          constructed_packet_len += SSH_UDPH_HDRLEN;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          /* Check if violating packet is UDP NAT-T. */
          for (i = 0; i < engine->num_ike_ports; i++)
            {
              if (((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
                   dst_port == engine->local_ike_natt_ports[i]) ||
                  ((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
                   dst_port == engine->remote_ike_natt_ports[i]))
                {
                  is_ike_natt = TRUE;
                  break;
                }
            }
          if (is_ike_natt
              && (offset + SSH_UDPH_HDRLEN + SSH_ESPH_OFS_SPI + 4) <= ip_len)
            {
              /* Copy from the SPI data to header and parse value. */
              ssh_interceptor_packet_copyout(pc->pp,
                                             offset + SSH_UDPH_HDRLEN
                                             + SSH_ESPH_OFS_SPI,
                                             payload, 4);
              /* Add SPI value after UDP header in the constructed packet. */
              spi = SSH_ESPH_SPI(payload);
              constructed_packet_len += 4;
            }
          else
            {
              is_ike_natt = FALSE;
            }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          break;

        case SSH_IPPROTO_UDPLITE:
          if (offset + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete UDPLITE header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          src_port = SSH_UDPH_DSTPORT(payload);
          dst_port = SSH_UDPH_SRCPORT(payload);
          constructed_packet_len += SSH_UDPH_HDRLEN;
          break;

        case SSH_IPPROTO_SCTP:
          if (offset + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete SCTP header but only
             ports are filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload, 4);
          dst_port = SSH_SCTPH_SRCPORT(payload);
          src_port = SSH_SCTPH_DSTPORT(payload);
          constructed_packet_len += SSH_SCTPH_HDRLEN;
          break;

          /* Dig out the SPI from AH and ESP headers. */
        case SSH_IPPROTO_AH:
          if (offset + SSH_AHH_OFS_SPI + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete AH header but only
             SPI value is filled in. */
          ssh_interceptor_packet_copyout(pc->pp,
                                         offset + SSH_AHH_OFS_SPI,
                                         payload, 4);
          spi = SSH_GET_32BIT(payload);
          constructed_packet_len += SSH_AHH_MINHDRLEN;
          break;

        case SSH_IPPROTO_ESP:
          if (offset + SSH_ESPH_OFS_SPI + 4 > ip_len)
            goto drop;

          /* Constructed packet has a complete ESP header but only
             SPI value is filled in. */
          ssh_interceptor_packet_copyout(pc->pp,
                                         offset + SSH_ESPH_OFS_SPI,
                                         payload, 4);
          spi = SSH_GET_32BIT(payload);
          constructed_packet_len += SSH_ESPH_HDRLEN;
          break;

        case SSH_IPPROTO_IPV6ICMP:
          if (offset + SSH_ICMP6H_HDRLEN > ip_len)
            goto drop;

          /* Constructed packet has at minimum four bytes of ICMP header
             but only type and code (and identifier for echo) values are
             filled in. */
          ssh_interceptor_packet_copyout(pc->pp, offset, payload,
                                         SSH_ICMP6H_HDRLEN);
          icmp_type = SSH_ICMP6H_TYPE(payload);
          icmp_code = SSH_ICMP6H_CODE(payload);
          constructed_packet_len += SSH_ICMP6H_HDRLEN;

          /* Copy icmp identifier to payload buf. */
          if (icmp_type == SSH_ICMP6_TYPE_ECHOREQUEST ||
              icmp_type == SSH_ICMP6_TYPE_ECHOREPLY)
            {
              if (offset + 6 > ip_len)
                goto drop;
              ssh_interceptor_packet_copyout(pc->pp,
                                             offset + SSH_ICMP6H_HDRLEN,
                                             payload, 2);
              payload_len = 2;
              constructed_packet_len += 4;
            }
          break;

        default:
          if (offset > ip_len)
            goto drop;

          /* Copy up to 8 bytes of payload for other protocols. */
          payload_len = 8;
          if (offset + payload_len > ip_len)
            payload_len = ip_len - offset;

          if (payload_len > 0)
            ssh_interceptor_packet_copyout(pc->pp, offset, payload,
                                           payload_len);
          constructed_packet_len += payload_len;
          break;
        }
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_NOTREACHED;
      goto drop;
    }

  /* Allocate a dummy packet for flow id computation */
  if (pc->pp->flags & SSH_PACKET_FROMADAPTER)
    constructed_packet_flags = SSH_PACKET_FROMADAPTER;
  else
    constructed_packet_flags = SSH_PACKET_FROMPROTOCOL;

  pp_ret = ssh_interceptor_packet_alloc(pc->engine->interceptor,
                                        constructed_packet_flags,
                                        constructed_packet_protocol,
                                        SSH_INTERCEPTOR_INVALID_IFNUM,
                                        SSH_INTERCEPTOR_INVALID_IFNUM,
                                        constructed_packet_len);
  if (pp_ret == NULL)
    goto drop;

  pp_ret->routing_instance_id = pc->pp->routing_instance_id;

  /* Build protocol headers to dummy packet. */
  ucp = ssh_interceptor_packet_pullup(pp_ret, constructed_packet_len);
  if (ucp == NULL)
    goto drop;
  memset(ucp, 0, constructed_packet_len);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    pp_ret->extension[i] = pp->extension[i];
#endif /* SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0 */

  /* Build incomplete IP header by filling in just the IP header
     version, length, IP protocol and address fields. Note that the
     constructed packet does not include any IPv4 header options or
     IPv6 extension headers that the original violating packet may
     have included. */
#ifdef WITH_IPV6
  if (constructed_packet_protocol == SSH_PROTOCOL_IP6)
    {
      SSH_IPH6_SET_VERSION(ucp, 6);
      SSH_IPH6_SET_LEN(ucp, constructed_packet_len - SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_SRC(&src, ucp);
      SSH_IPH6_SET_DST(&dst, ucp);
      SSH_IPH6_SET_NH(ucp, ipproto);
      offset = SSH_IPH6_HDRLEN;
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_IPH4_SET_VERSION(ucp, 4);
      SSH_IPH4_SET_HLEN(ucp, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucp, constructed_packet_len);
      SSH_IPH4_SET_SRC(&src, ucp);
      SSH_IPH4_SET_DST(&dst, ucp);
      SSH_IPH4_SET_PROTO(ucp, ipproto);
      offset = SSH_IPH4_HDRLEN;
    }

  /* Build incomplete transport header by filling in ports,
     SPI value for IPsec packets or ICMP identifier for ICMP echo. */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      SSH_TCPH_SET_SRCPORT(ucp + offset, src_port);
      SSH_TCPH_SET_DSTPORT(ucp + offset, dst_port);
      break;

    case SSH_IPPROTO_UDP:
      SSH_UDPH_SET_SRCPORT(ucp + offset, src_port);
      SSH_UDPH_SET_DSTPORT(ucp + offset, dst_port);
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if (is_ike_natt)
        SSH_ESPH_SET_SPI(ucp + offset + SSH_UDPH_HDRLEN, spi);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      break;

    case SSH_IPPROTO_UDPLITE:
      SSH_UDPH_SET_SRCPORT(ucp + offset, src_port);
      SSH_UDPH_SET_DSTPORT(ucp + offset, dst_port);
      break;

    case SSH_IPPROTO_SCTP:
      SSH_SCTPH_SET_SRCPORT(ucp + offset, src_port);
      SSH_SCTPH_SET_DSTPORT(ucp + offset, dst_port);
      break;

    case SSH_IPPROTO_ICMP:
      if (constructed_packet_protocol == SSH_PROTOCOL_IP4)
        {
          SSH_ICMPH_SET_TYPE(ucp + offset, icmp_type);
          SSH_ICMPH_SET_CODE(ucp + offset, icmp_code);
          offset += 4;
        }
      SSH_ASSERT(offset + payload_len <= constructed_packet_len);
      memcpy(ucp + offset, payload, payload_len);
      break;

    case SSH_IPPROTO_IPV6ICMP:
#ifdef WITH_IPV6
      if (constructed_packet_protocol == SSH_PROTOCOL_IP6)
        {
          SSH_ICMP6H_SET_TYPE(ucp + offset, icmp_type);
          SSH_ICMP6H_SET_CODE(ucp + offset, icmp_code);
          offset += 4;
        }
#endif /* WITH_IPV6 */
      SSH_ASSERT(offset + payload_len <= constructed_packet_len);
      memcpy(ucp + offset, payload, payload_len);
      break;

    case SSH_IPPROTO_ESP:
      SSH_ESPH_SET_SPI(ucp + offset, spi);
      break;

    case SSH_IPPROTO_AH:
      SSH_AHH_SET_SPI(ucp + offset, spi);
      break;

    default:
      SSH_ASSERT(offset + payload_len <= constructed_packet_len);
      memcpy(ucp + offset, payload, payload_len);
      break;
    }

  SSH_DUMP_PACKET(SSH_D_MY, ("original ICMP error packet"), pp);

  SSH_DUMP_PACKET(SSH_D_MY, ("Constructed inner packet"), pp_ret);

  ssh_engine_free_pc(engine, pc);
  return pp_ret;

 drop:
  SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner packet from purported "
                         "ICMP error message"));
  if (pc->pp)
    ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;
  ssh_engine_free_pc(engine, pc);
  return NULL;
}
