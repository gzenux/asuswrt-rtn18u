/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Media type handling for the fastpath. These functions are also called
   from the engine for NO_FLOW rules. This is a slight violation of the API,
   but one we are willing to live with for now, in the interest of footprint.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathMediatypes"

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Keep broken compilers that don't like empty source files happy. */
int fastpath_mediatypes_dummy;

#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Check if need to add media framing to packet 'pp'. This sets
   'pp->protocol' and 'pc->media_hdr_len' according to the added media
   header. On error this returns FALSE and 'pp' has been freed already. */
SSH_FASTTEXT Boolean
fastpath_insert_media_header(struct SshEnginePacketContextRec *pc,
                             SshInterceptorPacket pp)
{
#ifdef SSH_ENGINE_PAD_ETHERNET_FRAME
  size_t packet_len;
#endif /* SSH_ENGINE_PAD_ETHERNET_FRAME */
  size_t pad = 0;
  unsigned char *ucpw;

  SSH_ASSERT(pp != NULL);

  /* Check if media header needs to be added to the packet. */
  if (SSH_PREDICT_TRUE(pc->media_hdr_len == 0 && pc->u.flow.media_hdr_len > 0))
    {
      SSH_ASSERT(pc->u.flow.media_protocol != SSH_PROTOCOL_OTHER);

#ifdef SSH_ENGINE_PAD_ETHERNET_FRAME
      /* Pad at the end if necessary (e.g., ethernet packets have
         a minimum length of 60 bytes). */
      packet_len = pc->packet_len;

      SSH_ASSERT(packet_len == ssh_interceptor_packet_len(pp));
      if (SSH_PREDICT_FALSE(packet_len + pc->u.flow.media_hdr_len <
                            pc->u.flow.min_packet_len))
        {
          pad = pc->u.flow.min_packet_len - packet_len -
            pc->u.flow.media_hdr_len;
          ucpw = ssh_interceptor_packet_insert(pp, packet_len, pad);
          if (SSH_PREDICT_FALSE(!ucpw))
            {
              SSH_DEBUG(SSH_D_ERROR, ("Inserting media trailer pad failed"));
              return FALSE;
            }
          memset(ucpw, 0, pad);
        }
#endif /* SSH_ENGINE_PAD_ETHERNET_FRAME */

      /* Prepend the media header. */
      ucpw = ssh_interceptor_packet_insert(pp, 0, pc->u.flow.media_hdr_len);
      if (!ucpw)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Inserting media header failed"));
          return FALSE;
        }
      memcpy(ucpw, pc->u.flow.mediahdr, pc->u.flow.media_hdr_len);

      /* Mark that media framing has now been placed into the packet. */
      pc->media_hdr_len = pc->u.flow.media_hdr_len;
      pc->packet_len += pc->u.flow.media_hdr_len + pad;

      /* Update packet protocol according to the added media header. */
      pp->protocol = pc->u.flow.media_protocol;
    }

  return TRUE;
}

/* Update packet context's cached media header's source or destination
   media addresses for some special next-hop nodes.  The function
   handles two special cases in the media headers: for inbound
   next-hop nodes, it update's the packets source media address from
   the `pc->pp's cached media header that was stored there when the
   media framing was stripped from the packet.  For outbound packets
   to the `0.0.0.0' IP address, the function update's the packet's
   destination media address from the `pc->pp's cached media header to
   be the original media header.  The function does nothing if
   `pc->pp->pd's media protocol differs from `nh->media_protocol' or
   if the media type does not use media headers (plain interface). */
SSH_FASTTEXT void
fastpath_update_media_header(struct SshEnginePacketContextRec *pc,
                             struct SshEngineNextHopDataRec *nh,
                             Boolean dst_is_nulladdr)
{
  SshEnginePacketData pd;

  SSH_ASSERT(pc->pp != NULL);

  pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);

  if (SSH_PREDICT_FALSE(pd->media_protocol != nh->media_protocol))
    return;

  if (SSH_PREDICT_TRUE((SshInterceptorProtocol)nh->media_protocol
                       == SSH_PROTOCOL_ETHERNET))
    {
      if (SSH_PREDICT_FALSE(nh->flags & SSH_ENGINE_NH_INBOUND))
        {
          /* Take the source media address from the packet's original
             media header. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Updating ethernet source media address "
                     "to cached %@ for an inbound packet",
                     ssh_etheraddr_render, pd->mediahdr + SSH_ETHERH_OFS_SRC));
          memcpy(pc->u.flow.mediahdr + SSH_ETHERH_OFS_SRC,
                 pd->mediahdr + SSH_ETHERH_OFS_SRC,
                 SSH_ETHERH_ADDRLEN);
        }
      if (SSH_PREDICT_FALSE(nh->flags & SSH_ENGINE_NH_OUTBOUND) &&
          dst_is_nulladdr)
        {
          /* Take the destination media address from the packet's
             original media header. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Updating ethernet destination media address "
                     "to cached %@ for an outbound null-address packet",
                     ssh_etheraddr_render, pd->mediahdr + SSH_ETHERH_OFS_DST));
          memcpy(pc->u.flow.mediahdr + SSH_ETHERH_OFS_DST,
                 pd->mediahdr + SSH_ETHERH_OFS_DST,
                 SSH_ETHERH_ADDRLEN);
        }
      return;
    }

  /* Nothing to do for other protocols, just assert that protocol is sane. */
  SSH_ASSERT(nh->media_protocol < SSH_PROTOCOL_NUM_PROTOCOLS);
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
