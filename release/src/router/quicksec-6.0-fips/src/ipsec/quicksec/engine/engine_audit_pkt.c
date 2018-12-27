/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to audit corrupted packets.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineAuditPkt"

#ifdef SSHDIST_IPSEC_FIREWALL

/* Function prototype for analyzing packets */
#define SSH_ENGINE_FILTER_FUNC(x) \
static SshEngineAttackPacketType x(SshEngine engine, \
          SshEnginePacketCorruption reason, \
          SshEnginePacketContext pc, \
          SshInterceptorPacket pp, \
          const unsigned char **ucp, \
          size_t *len)

typedef SshEngineAttackPacketType
(*SshEnginePktFilterCB)(SshEngine engine,
                        SshEnginePacketCorruption reason,
                        SshEnginePacketContext pc,
                        SshInterceptorPacket pp,
                        const unsigned char **ucp,
                        size_t *len);

/* Wrapper for the analysis functions */
static SshEngineAttackPacketType
ssh_engine_packet_is_attack(SshEngine engine,
                            SshEnginePacketCorruption reason,
                            SshEnginePacketContext pc,
                            SshInterceptorPacket pp,
                            const unsigned char **ucp,
                            size_t *len);
















































/* LAND Attack is a TCP/IP packet such that
   ipproto=tcp src_ip = dst_ip and src_port = dst_port. */
SSH_ENGINE_FILTER_FUNC(ssh_engine_attack_land)
{
  const unsigned char *p;
  size_t offset;

  offset = 0;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  offset = pc->media_hdr_len;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (pc->packet_len < pc->hdrlen + SSH_TCPH_HDRLEN)
    /* It is not a valid TCP packet. */
    return SSH_ENGINE_ATTACK_NONE;

  if (((offset + pc->hdrlen + SSH_TCPH_HDRLEN) >
       SSH_INTERCEPTOR_MAX_PULLUP_LEN) ||
      ((offset + pc->hdrlen + SSH_TCPH_HDRLEN) >
       pc->packet_len))
    {
      /* We can't pullup enough data, drop the packet
         and return error. */
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);

      pc->pp = NULL;
      return SSH_ENGINE_ATTACK_INTERNAL_ERROR;
    }

  /* Assume packets are truncated, which they should be */
  *ucp = ssh_interceptor_packet_pullup_read(pp,
                                            offset + pc->hdrlen
                                            + SSH_TCPH_HDRLEN);
  if (*ucp == NULL)
    {
      pc->pp = NULL;
      return SSH_ENGINE_ATTACK_INTERNAL_ERROR;
    }

  *len = pc->hdrlen + SSH_TCPH_HDRLEN - offset;
  *ucp += offset;

  if (SSH_IPH4_VERSION(*ucp) != 4)
    return SSH_ENGINE_ATTACK_NONE;

  p = *ucp;
  if (pc->ipproto != SSH_IPPROTO_TCP
      || (memcmp(p + SSH_IPH4_OFS_DST, p+SSH_IPH4_OFS_SRC,4) != 0)
      || (memcmp(p + SSH_IPH4_HDRLEN + SSH_TCPH_OFS_SRCPORT,
                 p + SSH_IPH4_HDRLEN + SSH_TCPH_OFS_DSTPORT,
                 2) != 0))
    return SSH_ENGINE_ATTACK_NONE;

  return SSH_ENGINE_ATTACK_LAND;
}

/* Map packet corruptions directly to attacks, if possible. */
SSH_ENGINE_FILTER_FUNC(ssh_engine_attack_corruption_map)
{
  switch (reason)
    {
      /* "Ping of Death" is an attack against the reassembly code in a
         TCP/IP stack. A set of fragments is constructed and sent
         such that the reassembled packet will exceed the maximum
         length of a IP packet (2^16-1 bytes). */
    case SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH:
      return SSH_ENGINE_ATTACK_FRAGMENT_DEATH;

      /* Traceroute's can be detected by dropping packets with a too low
         TTL. Also certain Linux kernels leak contents of kernel memory
         via TTL exceeded ICMP responses. [CVE-2002-0046] */
    case SSH_PACKET_CORRUPTION_TTL_SMALL:
      return SSH_ENGINE_ATTACK_TRACEROUTE;

    case SSH_PACKET_CORRUPTION_TCP_XMAS:
      return SSH_ENGINE_ATTACK_XMAS_SCAN;

    case SSH_PACKET_CORRUPTION_TCP_FIN:
      return SSH_ENGINE_ATTACK_FIN_SCAN;

    case SSH_PACKET_CORRUPTION_TCP_NULL:
      return SSH_ENGINE_ATTACK_NULL_SCAN;

    default:
      return SSH_ENGINE_ATTACK_NONE;
    }
  /*NOTREACHED*/
}

































































































































































/* Simple structure for mapping between attack id's and function pointers */
typedef struct SshEnginePktFilterRec
{
  SshEngineAttackPacketType type;
  SshEnginePktFilterCB filter;
} *SshEnginePktFilter, SshEnginePktFilterStruct;

SSH_RODATA
const SshEnginePktFilterStruct ssh_pkt_filters[] =
{
  /* Detect the LAND attack */
  { SSH_ENGINE_ATTACK_LAND,           ssh_engine_attack_land },
  /* Handle simple corruption reason->attack maps */
  { SSH_ENGINE_ATTACK_FRAGMENT_DEATH, ssh_engine_attack_corruption_map },
  /* Previous detector hook handles these */
  { SSH_ENGINE_ATTACK_SMURF,          NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_FRAGGLE,        NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_TRACEROUTE,     NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_XMAS_SCAN,      NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_NULL_SCAN,      NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_FIN_SCAN,       NULL_FNPTR, },
  { SSH_ENGINE_ATTACK_NONE,           NULL_FNPTR, }
};

#endif /* SSHDIST_IPSEC_FIREWALL */

#ifdef SSHDIST_IPSEC_FIREWALL

static SshEngineAttackPacketType
ssh_engine_packet_is_attack(SshEngine engine,
                            SshEnginePacketCorruption reason,
                            SshEnginePacketContext pc,
                            SshInterceptorPacket pp,
                            const unsigned char **ucp,
                            size_t *len)
{
  int i;
  SshEngineAttackPacketType t;

  for (i = 0; ssh_pkt_filters[i].type != SSH_ENGINE_ATTACK_NONE; i++)
    {
      if (ssh_pkt_filters[i].filter)
        {
          t = ssh_pkt_filters[i].filter(engine, reason,
                                        pc, pp, ucp, len);
          if (t != SSH_ENGINE_ATTACK_NONE)
            return t;

          /* Pull up failed and contract is void, abort. */
          if (*ucp == NULL)
            return SSH_ENGINE_ATTACK_NONE;
        }
    }
  return SSH_ENGINE_ATTACK_NONE;
}

#endif /* SSHDIST_IPSEC_FIREWALL */

static SshAuditEvent
ssh_engine_packet_corruption_to_audit_event(SshEnginePacketCorruption reason)
{
  switch (reason)
    {
    case SSH_PACKET_CORRUPTION_POLICY_DROP:
    case SSH_PACKET_CORRUPTION_POLICY_REJECT:
    case SSH_PACKET_CORRUPTION_POLICY_PASS:
      return SSH_AUDIT_RULE_MATCH;

    case SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_OVERFLOW:
      return SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW;

     case SSH_PACKET_CORRUPTION_AH_IP_FRAGMENT:
      return SSH_AUDIT_AH_IP_FRAGMENT;

    case SSH_PACKET_CORRUPTION_AH_SA_LOOKUP_FAILURE:
      return SSH_AUDIT_AH_SA_LOOKUP_FAILURE;

    case SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE:
      return SSH_AUDIT_AH_SEQUENCE_NUMBER_FAILURE;

    case SSH_PACKET_CORRUPTION_AH_ICV_FAILURE:
      return SSH_AUDIT_AH_ICV_FAILURE;

    case SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_OVERFLOW:
      return SSH_AUDIT_ESP_SEQUENCE_NUMBER_OVERFLOW;

    case SSH_PACKET_CORRUPTION_ESP_IP_FRAGMENT:
      return SSH_AUDIT_ESP_IP_FRAGMENT;

    case SSH_PACKET_CORRUPTION_ESP_SA_LOOKUP_FAILURE:
      return SSH_AUDIT_ESP_SA_LOOKUP_FAILURE;

    case SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE:
      return SSH_AUDIT_ESP_SEQUENCE_NUMBER_FAILURE;

    case SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE:
      return SSH_AUDIT_ESP_ICV_FAILURE;

    case SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL:
      return SSH_AUDIT_CHECKSUM_COVERAGE_FIELD_INVALID;

    default:
      return SSH_AUDIT_CORRUPT_PACKET;
    }
}

/* Reinject the packet back to the fastpath after auditing. */
static void
engine_audit_packet_context_finish(SshEngine engine,
                                   SshEnginePacketContext pc)
{
  SshEnginePacketCorruption corruption = pc->audit.corruption;
  SshEngineActionRet ret = SSH_ENGINE_RET_DROP;

  /* Clear auditing information */
  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;
  pc->audit.ip_option = 0;
  pc->audit.spi = 0;

  switch (corruption)
    {
    case SSH_PACKET_CORRUPTION_POLICY_PASS:
      engine_packet_continue(pc, SSH_ENGINE_RET_EXECUTE);
      return;

    case SSH_PACKET_CORRUPTION_POLICY_REJECT:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RULEREJECT);
      break;

    default:
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
      break;
    }

  if (pc->error_info.flags & SSH_ENGINE_SEND_ICMP_ERROR)
    ssh_engine_send_icmp_error(engine, pc, pc->error_info.icmp_type,
                               pc->error_info.icmp_code,
                               pc->error_info.icmp_extra_data);

  else if (pc->error_info.flags & SSH_ENGINE_SEND_TCP_REJECT)
    ssh_engine_send_tcp_rst(engine, pc);

  pc->error_info.flags = 0;

  engine_packet_continue(pc, ret);
  return;
}

void
ssh_engine_audit_packet_context(SshEngine engine,
                                SshEnginePacketContext pc)
{
  const unsigned char *ucp, *src_ip, *dst_ip, *media_hdr = NULL;
  size_t ip_len, len;
  size_t media_hdr_len = 0, real_packet_len = 0;
  SshEngineAttackPacketType attack_type;
  SshUInt32 to_tunnel_id;
  SshEngineIfnum dst_ifnum;
  SshEngineTransformControl c_trd;
  SshEnginePacketCorruption reason = pc->audit.corruption;
  SshAuditEvent event;
  SshEngineAuditEvent c;
  SshUInt32 index;

  SSH_DEBUG(SSH_D_MY, ("sending audit event to PM"));

  SSH_INTERCEPTOR_STACK_MARK();

  /* At this point context_pullup() HAS BEEN RUN */

  SSH_ASSERT(pc->pp != NULL);

  if ((pc->hdrlen < SSH_IPH4_HDRLEN) && pc->pp->protocol == SSH_PROTOCOL_IP4)
    goto fail;

#if defined (WITH_IPV6)
  if ((pc->hdrlen < SSH_IPH6_HDRLEN) && pc->pp->protocol == SSH_PROTOCOL_IP6)
    goto fail;
#endif /* WITH_IPV6 */

  /* Do not log packets which are "obvious garbage"
     (e.g. errors analoguous to checksum being incorrect). */
  if (reason == SSH_PACKET_CORRUPTION_ERROR
      || reason == SSH_PACKET_CORRUPTION_SHORT_MEDIA_HEADER
      || reason == SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER
      || reason == SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER
      || reason == SSH_PACKET_CORRUPTION_NOT_IPV4
      || reason == SSH_PACKET_CORRUPTION_NOT_IPV6
      || reason == SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH
      || reason == SSH_PACKET_CORRUPTION_TRUNCATED_PACKET)
    goto fail;

#ifdef  SSHDIST_IPSEC_FIREWALL
  /* Diagnosis to see if it is an attack */
  attack_type = ssh_engine_packet_is_attack(engine, reason,
                                            pc, pc->pp, &ucp, &len);
#else /* SSHDIST_IPSEC_FIREWALL */
  /* Attack detection is only performed if SSHDIST_IPSEC_FIREWALL
     is set to save on footprint. */
  attack_type = SSH_ENGINE_ATTACK_NONE;
#endif /* SSHDIST_IPSEC_FIREWALL */

  if (attack_type == SSH_ENGINE_ATTACK_INTERNAL_ERROR)
    {
      /* pp has already been freed.  */
      pc->pp = NULL;
      engine_packet_continue(pc, SSH_ENGINE_RET_ERROR);
      return;
    }

  event = ssh_engine_packet_corruption_to_audit_event(reason);

  if (pc->hdrlen + SSH_TCPH_HDRLEN < pc->packet_len)
    len = pc->hdrlen + SSH_TCPH_HDRLEN;
  else if (pc->hdrlen + 4 < pc->packet_len)
    len = pc->hdrlen + 4;
  else
    len = pc->hdrlen;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  len += pc->media_hdr_len;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* For pullup; we only allow SSH_INTERCEPTOR_MAX_PULLUP_LEN octets */
  if (len > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    len = SSH_INTERCEPTOR_MAX_PULLUP_LEN;

  /* Check if we can pull enough data for our purposes. If
     not, just get rid of the packet. */
  if (len > pc->packet_len)
    {
      goto fail;
    }

  ucp = ssh_interceptor_packet_pullup_read(pc->pp, len);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      engine_packet_continue(pc, SSH_ENGINE_RET_ERROR);
      return;
    }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (pc->media_hdr_len > 0)
    {
      media_hdr = ucp;
      media_hdr_len = pc->media_hdr_len;
    }

  ucp += pc->media_hdr_len;
  len -= pc->media_hdr_len;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (SSH_IPH4_VERSION(ucp) != 4 && SSH_IPH6_VERSION(ucp) != 6)
    goto fail;

  if (SSH_IPH4_VERSION(ucp) == 4)
    {
      src_ip = ucp + SSH_IPH4_OFS_SRC;
      dst_ip = ucp + SSH_IPH4_OFS_DST;
      ip_len = 4;
    }
  else
    {
      SSH_ASSERT(SSH_IPH4_VERSION(ucp) == 6);
      src_ip = ucp + SSH_IPH6_OFS_SRC;
      dst_ip = ucp + SSH_IPH6_OFS_DST;
      ip_len = 16;
    }

  to_tunnel_id = 0;

  if (pc->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);

      c_trd = SSH_ENGINE_GET_TRD(engine, pc->transform_index);
      if (c_trd != NULL)
        {
          SshEngineTransformData d_trd;

          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                             pc->transform_index);
          to_tunnel_id = d_trd->inbound_tunnel_id;
          FASTPATH_RELEASE_TRD(engine->fastpath, pc->transform_index);
        }
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
    }

  /* This is a slightly ugly hack, as it means that we rely
     on "reason" for denoting what values in 'pc' are valid,
     but the other options (other function, more parameters)
     seem less attractive. */
  dst_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  if (reason == SSH_PACKET_CORRUPTION_POLICY_PASS)
    dst_ifnum = pc->u.flow.ifnum;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Select the audit queue where to queue this event. */
  switch (event)
    {
    case SSH_AUDIT_ENGINE_SESSION_START:
    case SSH_AUDIT_ENGINE_SESSION_END:
    case SSH_AUDIT_WARNING:
    case SSH_AUDIT_NOTICE:
    case SSH_AUDIT_RESOURCE_FAILURE:
      index = SSH_ENGINE_AUDIT_LEVEL_INFORMATIONAL;
      break;
    default:
      index = SSH_ENGINE_AUDIT_LEVEL_CORRUPTION;
      break;
    }
  SSH_ASSERT(index < SSH_ENGINE_NUM_AUDIT_LEVELS);

  /* Rate limit */
  if (ssh_engine_audit_rate_limit(engine, index) == TRUE)
    {
      engine->audit_flags |= SSH_ENGINE_AUDIT_RATE_LIMITED_EVENT;

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      goto fail;
    }

  /* Check if we have space to audit this event, if not we return
     without auditing it. */
  if (engine->audit_table_head[index] ==
      SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_tail[index]))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("No space on the audit queue to audit this event"));

      engine->audit_flags |= SSH_ENGINE_AUDIT_EVENT_FAILURE;

      engine_audit_busy(engine);

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      goto fail;
    }

  c = &engine->audit_table[index][engine->audit_table_tail[index]];

  /* Move tail pointer ahead one slot. */
  engine->audit_table_tail[index] =
    SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_tail[index]);

  engine_audit_new_event(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  memset(c, 0, sizeof(*c));

  engine->audit_event_id++;
  c->audit_id = engine->audit_event_id;

  c->engine = engine;
  c->event = event;
  SSH_IP_DECODE(&c->src_ip, src_ip, ip_len);
  SSH_IP_DECODE(&c->dst_ip, dst_ip, ip_len);
  c->ipproto = pc->ipproto;
  c->ipv4_option = (SshUInt8) pc->audit.ip_option;
  c->packet_corruption = reason;
  c->packet_attack = attack_type;
  c->src_ifnum = pc->pp->ifnum_in;
  c->dst_ifnum = dst_ifnum;
  c->from_tunnel_id = pc->tunnel_id;
  c->to_tunnel_id = to_tunnel_id;
  c->spi = pc->audit.spi;
  c->seq = pc->audit.seq;
  c->flowlabel = pc->audit.flowlabel;
  c->packet = NULL;
  c->packet_len = 0;
  c->real_packet_len = real_packet_len;
  SSH_ASSERT(media_hdr_len <= sizeof(c->mediahdr));

  c->mediahdr_len = media_hdr_len;
  if (media_hdr)
    memcpy(c->mediahdr, media_hdr, media_hdr_len);

  /* TCP and UDP port numbers reside in the same place in the header */
  if (pc->ipproto == SSH_IPPROTO_TCP
      || pc->ipproto == SSH_IPPROTO_UDP
      || pc->ipproto == SSH_IPPROTO_UDPLITE)
    {
      if (len >= pc->hdrlen + 4)
        {
          c->src_port =
            SSH_GET_16BIT(ucp + pc->hdrlen + SSH_TCPH_OFS_SRCPORT);
          c->dst_port =
            SSH_GET_16BIT(ucp + pc->hdrlen + SSH_TCPH_OFS_DSTPORT);
        }
      else
        {
          c->validity_flags |= SSH_ENGINE_AUDIT_NONVALID_PORTS;
        }

      if (pc->ipproto == SSH_IPPROTO_TCP
          && (len >= pc->hdrlen + SSH_TCPH_OFS_FLAGS + 1))
        {
          c->tcp_flags = *(ucp  + pc->hdrlen + SSH_TCPH_OFS_FLAGS);
        }
      else
        {
          c->validity_flags |= SSH_ENGINE_AUDIT_NONVALID_TCPFLAGS;
        }
    }
  else if (pc->ipproto == SSH_IPPROTO_ICMP ||
           pc->ipproto == SSH_IPPROTO_IPV6ICMP)
    {
      if (len >= pc->hdrlen + 2)
        {
          c->icmp_type =
            *((SshUInt8 *)(ucp + pc->hdrlen + SSH_ICMPH_OFS_TYPE));
          c->icmp_code =
            *((SshUInt8 *)(ucp + pc->hdrlen + SSH_ICMPH_OFS_CODE));
        }
      else
        {
          c->validity_flags |= SSH_ENGINE_AUDIT_NONVALID_PORTS;
        }
    }

  /* New entry on audit queue is ready. */
  engine_audit_packet_context_finish(engine, pc);
  return;

 fail:

  if ((pc->flags & SSH_ENGINE_PC_ENFORCE_AUDIT) != 0)
    {
      /* Clear auditing information */
      pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;
      pc->audit.ip_option = 0;
      pc->audit.spi = 0;
      pc->audit.seq = 0;
      pc->audit.flowlabel = 0;

      SSH_DEBUG(SSH_D_FAIL, ("Cannot audit this event, and policy enforces "
                             "the packet to be dropped."));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_RESOURCEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_DROP);
      return;
    }
  else
    {
      engine_audit_packet_context_finish(engine, pc);
      return;
    }
}
