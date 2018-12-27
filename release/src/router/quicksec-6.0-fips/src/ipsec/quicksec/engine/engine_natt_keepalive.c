/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   NAT traversal keepalive message generation.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineNattKeepalive"

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

/* This function gets called regularly from a timeout.  This traverses
   through the engine's list of transforms requiring NAT-T keepalive
   messages and sends the keepalive packets. */

void ssh_engine_natt_keepalive_timeout(void *context)
{
  SshEngine engine = (SshEngine) context;
  SshUInt32 trd_index;
  SshEngineTransformControl c_trd = NULL, c_trd2;
  SshEngineTransformData d_trd, d_trd2;
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshUInt16 src_port;
  SshUInt16 dst_port;
  SshEngineIfnum ifnum_in;
  SshUInt16 ip_id;
  SshUInt16 cksum;
  SshUInt32 hashvalue;
  SshInterceptorPacket pp;
  SshInterceptorProtocol protocol;
  size_t len;
  unsigned char *ucpw;

  SSH_DEBUG(SSH_D_HIGHSTART, ("NAT-T keepalive timeout"));

  /* Process all unprocessed entries in the list. */
  while (1)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);

      /* Find the next unprocessed entry. */
      for (trd_index = engine->natt_keepalive;
           trd_index != SSH_IPSEC_INVALID_INDEX;
           trd_index = c_trd->natt_keepalive_next)
        {
          c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
          SSH_ASSERT(c_trd != NULL);
          SSH_ASSERT(c_trd->control_flags
                     & SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED);

          if ((c_trd->control_flags & SSH_ENGINE_TR_C_NATT_KEEPALIVE_SENT)
              == 0)
            /* Found an unprocessed entry. */
            break;
        }

      /* Check if we found any transforms. */
      if (trd_index == SSH_IPSEC_INVALID_INDEX)
        /* No more entries found. */
        break;

      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_index);

      /* Found an unprocessed entry.  First, mark it processed so that
         if the keepalive packet sending fails, we won't stuck on this
         entry on restart. */
      c_trd->control_flags |= SSH_ENGINE_TR_C_NATT_KEEPALIVE_SENT;

      /* Fetch all interesting parameters from the transform. */
      src = d_trd->own_addr;
      dst = d_trd->gw_addr;

      dst_port = d_trd->remote_port;
      ifnum_in = d_trd->own_ifnum;
      src_port = d_trd->local_port;

      FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);

      /* Allocate an IP ID for the keepalive packet. */
      ip_id = ssh_engine_get_ip_id(engine);

      /* Mark all NAT-T keepalive transforms with the same peer as
         processed. */
      hashvalue = SSH_IP_HASH(&dst) % SSH_ENGINE_PEER_HASH_SIZE;
      for (trd_index = engine->peer_hash[hashvalue];
           trd_index != SSH_IPSEC_INVALID_INDEX;
           trd_index = c_trd2->peer_next)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, trd_index);
          d_trd2 = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_index);
          SSH_ASSERT(c_trd2 != NULL);

          /* Compare the 'remote_port' and 'gw_addr' fields of d_trd2
             and d_trd (whose values are copied to 'dst_port' and 'dst'). */
          if ((c_trd2->control_flags & SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED)
              && SSH_IP_EQUAL(&dst, &d_trd2->gw_addr)
              && dst_port == d_trd2->remote_port)
            {
              /* Found a matching transform.  Mark it as processed too. */
              c_trd2->control_flags |= SSH_ENGINE_TR_C_NATT_KEEPALIVE_SENT;
            }
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
        }

      /* Release the flow control table lock and send the keepalive packet. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      SSH_DEBUG(SSH_D_HIGHOK, ("Sending keepalive %@.%d->%@.%d",
                               ssh_ipaddr_render, &src,
                               (int) src_port,
                               ssh_ipaddr_render, &dst,
                               (int) dst_port));

      if (SSH_IP_IS4(&src))
        {
          protocol = SSH_PROTOCOL_IP4;
          len = SSH_IPH4_HDRLEN + SSH_UDPH_HDRLEN;
        }
      else
        {
          protocol = SSH_PROTOCOL_IP6;
          len = SSH_IPH6_HDRLEN + SSH_UDPH_HDRLEN;
        }

      /* The length of the UDP payload. One byte payload. */
      len += 1;

      if (c_trd->routing_instance_id < 0)
        continue;

      pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                        SSH_PACKET_FROMPROTOCOL,
                                        protocol, ifnum_in,
                                        SSH_INTERCEPTOR_INVALID_IFNUM, len);
      if (pp == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not allocate packet for NAT-T keepalive"));
          /* Continue processing the keepalive list. */
          continue;
        }

      /* Set routing instance id */
      pp->routing_instance_id = c_trd->routing_instance_id;

      /* Pullup the whole packet. */
      ucpw = ssh_interceptor_packet_pullup(pp, len);
      if (ucpw == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Pullup failed"));
          continue;
        }

      /* Format NAT-T keepalive packet. */

      memset(ucpw, 0, len);

      /* IP header. */

      if (protocol == SSH_PROTOCOL_IP4)
        {
          SSH_IPH4_SET_VERSION(ucpw, 4);
          SSH_IPH4_SET_HLEN(ucpw, SSH_IPH4_HDRLEN / 4);
          SSH_IPH4_SET_LEN(ucpw, len);
          SSH_IPH4_SET_ID(ucpw, ip_id);
          SSH_IPH4_SET_TTL(ucpw, 240);
          SSH_IPH4_SET_PROTO(ucpw, SSH_IPPROTO_UDP);
          SSH_IPH4_SET_SRC(&src, ucpw);
          SSH_IPH4_SET_DST(&dst, ucpw);

          cksum = ssh_ip_cksum(ucpw, SSH_IPH4_HDRLEN);
          SSH_IPH4_SET_CHECKSUM(ucpw, cksum);

          ucpw += SSH_IPH4_HDRLEN;
        }
      else
        {
          SSH_IPH6_SET_VERSION(ucpw, 6);
          SSH_IPH6_SET_CLASS(ucpw, 0);
          SSH_IPH6_SET_FLOW(ucpw, 0);
          SSH_IPH6_SET_LEN(ucpw, len - SSH_IPH6_HDRLEN);
          SSH_IPH6_SET_NH(ucpw, SSH_IPPROTO_UDP);
          SSH_IPH6_SET_HL(ucpw, 240);
          SSH_IPH6_SET_SRC(&src, ucpw);
          SSH_IPH6_SET_DST(&dst, ucpw);

          ucpw += SSH_IPH6_HDRLEN;
        }

      /* UDP header. */
      SSH_UDPH_SET_SRCPORT(ucpw, src_port);
      SSH_UDPH_SET_DSTPORT(ucpw, dst_port);
      SSH_UDPH_SET_LEN(ucpw, SSH_UDPH_HDRLEN + 1);

      ucpw += SSH_UDPH_HDRLEN;

      /* NAT-T header. */
      ucpw[0] = 0xff;











      /* Send the packet to the fastpath. */
      (void) ssh_engine_packet_start(engine, pp, 0, SSH_IPSEC_INVALID_INDEX,
                                     0);

      /* Continue processing more entries from the NAT-T keepalive
         list. */
    }

  /* All entries processed.  Scan the list one more time and clear the
     sent flags. */
  for (trd_index = engine->natt_keepalive;
       trd_index != SSH_IPSEC_INVALID_INDEX;
       trd_index = c_trd->natt_keepalive_next)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(c_trd->control_flags
                 & SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED);
      c_trd->control_flags &= ~SSH_ENGINE_TR_C_NATT_KEEPALIVE_SENT;
    }

  /* Reschedule the keepalive timeout. */
  if (engine->natt_keepalive_interval > 0)
    ssh_kernel_timeout_register(engine->natt_keepalive_interval, 0,
                                ssh_engine_natt_keepalive_timeout, context);

  /* Unlock the flow table lock. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
