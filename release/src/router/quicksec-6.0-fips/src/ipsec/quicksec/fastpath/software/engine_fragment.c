/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Fragmentation code for outgoing IP (v4 or v6) packets.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathFragment"

/* Initializes the fragmentation context for fragmenting the given
   packet.  This returns TRUE if the packet has the DF bit set (in
   which case `pc->pp' is not freed, and ssh_fastpath_fragc_uninit
   should not be called), and otherwise returns FALSE (in which case
   `pc->pp' is freed either by this function or by a later call to
   ssh_fastpath_fragc_uninit). */

Boolean ssh_fastpath_fragc_init(SshFastpath fastpath,
                                SshFastpathFragmentContext fragc,
                                SshEnginePacketContext pc,
                                size_t mtu,
                                Boolean df_on_first_fragment)
{
  SshInterceptorPacket pp = pc->pp;
  size_t packet_len = pc->packet_len;

  /* Initialize common fields in the fragment context. */
  fragc->pp = pp;
  fragc->mtu = mtu;
  fragc->offset = 0;

#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      SshUInt16 frag_hlen;
      SshUInt16 frag_data_len;

      if ((pp->flags & SSH_PACKET_FRAGMENTATION_ALLOWED) == 0
          || (pp->flags & SSH_ENGINE_P_ISFRAG) != 0)
        {
          /* Refuse to fragment something already fragmented */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Refusing to fragment IPv6 packet: flags 0x%08lx",
                     (unsigned long) pp->flags));
          return TRUE;
        }

      fragc->total_len = packet_len - pc->fragh_offset;

      /* Compute fragments' header and data lengths. */
      frag_hlen = pc->fragh_offset + SSH_IP6_EXT_FRAGMENT_HDRLEN;
      frag_data_len = ((size_t) (mtu - frag_hlen)) & (size_t) ~7;
      SSH_ASSERT(frag_data_len > 0 && frag_data_len <= 65535 - frag_hlen);

      /* Store that information into the fragmentation context. */
      fragc->frag_hlen = frag_hlen;
      fragc->frag_data_len = frag_data_len;

      fragc->u.ipv6.fragh_offset = pc->fragh_offset;
      fragc->u.ipv6.fragh_offset_prevnh = pc->fragh_offset_prevnh;

      ssh_kernel_mutex_lock(fastpath->frag_lock);
      fragc->u.ipv6.id = fastpath_get_ipv6_frag_id(fastpath);
      ssh_kernel_mutex_unlock(fastpath->frag_lock);
    }
  else
#endif /* WITH_IPV6 */
    {
      const unsigned char *orig_ucp;
      size_t hdrlen = pc->hdrlen;
      SshUInt32 i;
      SshUInt16 frag_optlen, frag1_optlen;
      SshUInt16 frag_hlen, frag1_hlen;
      SshUInt16 frag_data_len, frag1_data_len;
      SshUInt16 optlen;
      SshUInt8 opttype;
      SshUInt16 ip_id;

      /* Get a pointer to the packet to be fragmented. */
      orig_ucp = ssh_interceptor_packet_pullup_read(pp, hdrlen);
      if (orig_ucp == NULL)
        {
          /* pp is now invalid. */
          pc->pp = NULL;
          fragc->pp = NULL;
          SSH_DEBUG(SSH_D_ERROR,
                    ("can't pullup IP header from the fragment to be sent."));
          return FALSE;
        }

      /* Check if the packet has DF bit set. */
      if ((SSH_IPH4_FRAGOFF(orig_ucp) & SSH_IPH4_FRAGOFF_DF) != 0
          && (pc->pp->flags & SSH_PACKET_FRAGMENTATION_ALLOWED) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Refusing to fragment IPv4 packet: df %d",
                     (SSH_IPH4_FRAGOFF(orig_ucp) & SSH_IPH4_FRAGOFF_DF) ?
                     1 : 0));
          return TRUE;
        }

      fragc->u.ipv4.hdrlen = hdrlen;
      fragc->total_len = packet_len - hdrlen;
      fragc->u.ipv4.df_on_first_fragment = df_on_first_fragment;

      /* Determine how much space to reserve for IP options in each packet. */
      frag_optlen = 0;
      frag1_optlen = 0;
      for (i = SSH_IPH4_HDRLEN; i < hdrlen; i += optlen)
        {
          opttype = orig_ucp[i];
          if (opttype == SSH_IPOPT_EOL)
            break;
          if (opttype == SSH_IPOPT_NOP)
            optlen = 1;
          else
            optlen = orig_ucp[i + 1];
          if (optlen > hdrlen - i || hdrlen < 1)
            optlen = hdrlen - i; /* should never legally happen, but
                                    be safe...*/
          if (SSH_IPOPT_COPIED(opttype))
            {
              memcpy(&fragc->u.ipv4.frag_options[frag_optlen],
                     orig_ucp + i,
                     optlen);
              frag_optlen += optlen;
            }

          memcpy(&fragc->u.ipv4.frag1_options[frag1_optlen],
                 &orig_ucp[i],
                 optlen);
          frag1_optlen += optlen;
        }
      while (frag_optlen & 0x03)
        fragc->u.ipv4.frag_options[frag_optlen++] = SSH_IPOPT_EOL;

      while (frag1_optlen & 0x03)
        fragc->u.ipv4.frag1_options[frag1_optlen++] = SSH_IPOPT_EOL;

      frag_hlen = SSH_IPH4_HDRLEN + frag_optlen;
      SSH_ASSERT((frag_hlen & 3) == 0 &&
                 frag_optlen <= sizeof(fragc->u.ipv4.frag_options));

      frag1_hlen = SSH_IPH4_HDRLEN + frag1_optlen;
      SSH_ASSERT((frag1_hlen & 3) == 0 &&
                 frag1_optlen <= sizeof(fragc->u.ipv4.frag1_options));

      /* Compute amount of data to go in fragments. */
      frag_data_len = ((size_t) (mtu - frag_hlen)) & (size_t) ~7;
      SSH_ASSERT(frag_data_len > 0 && frag_data_len <= 65535 - frag_hlen);

      frag1_data_len = ((size_t) (mtu - frag1_hlen)) & (size_t) ~7;
      SSH_ASSERT(frag1_data_len > 0 && frag1_data_len <= 65535 - frag1_hlen);

      /* Store computed values into the fragmentation context. */
      memcpy(fragc->u.ipv4.frag_hdr, orig_ucp, SSH_IPH4_HDRLEN);

      /* Is the IP ID already set? */
      if (SSH_IPH4_ID(fragc->u.ipv4.frag_hdr) == 0)
        {
          /* No, let's generate one... */
          ip_id = ssh_engine_get_ip_id(fastpath->engine);
          SSH_IPH4_SET_ID(fragc->u.ipv4.frag_hdr, ip_id);
        }

      fragc->u.ipv4.frag_optlen = frag_optlen;
      fragc->u.ipv4.frag1_optlen = frag1_optlen;
      fragc->frag_hlen = frag_hlen;
      fragc->u.ipv4.frag1_hlen = frag1_hlen;
      fragc->frag_data_len = frag_data_len;
      fragc->u.ipv4.frag1_data_len = frag1_data_len;
    }

  return FALSE;
}

/* Returns the next fragment for the packet, or NULL if there are
   no more fragments.  This also returns NULL if an error occurs. */

SshInterceptorPacket
ssh_fastpath_fragc_next(SshFastpath fastpath,
                        SshFastpathFragmentContext fragc)
{
  SshUInt16 this_hlen, this_data_len, this_optlen, len, offset_orig;
  SshUInt16 fragoff_orig, fragoff, checksum;
  const unsigned char *this_options;
  SshInterceptorPacket frag;
  Boolean is_last_frag;
  unsigned char *ucp;
  SshInterceptor interceptor = fastpath->engine->interceptor;

  /* If an error caused pp to be freed, return NULL to indicate we are
     done. */
  if (fragc->pp == NULL || fragc->offset >= fragc->total_len)
    return NULL;

  /* Determine correct frag_hlen for this packet */
#if defined (WITH_IPV6)
  if (fragc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      this_hlen = fragc->frag_hlen;
      this_data_len = fragc->frag_data_len;
      /* The following assignments are here only to keep the compiler
         quiet. */
      this_options = NULL;
      this_optlen = 0;
    }
  else
#endif /* WITH_IPV6 */
    {
      if (fragc->offset == 0)
        {
          this_hlen = fragc->u.ipv4.frag1_hlen;
          this_data_len = fragc->u.ipv4.frag1_data_len;
          this_options = fragc->u.ipv4.frag1_options;
          this_optlen = fragc->u.ipv4.frag1_optlen;
        }
      else
        {
          this_hlen = fragc->frag_hlen;
          this_data_len = fragc->frag_data_len;
          this_options = fragc->u.ipv4.frag_options;
          this_optlen = fragc->u.ipv4.frag_optlen;
        }
    }

  /* Determine the length of the data section of the fragment. */
  if (fragc->offset + this_data_len < fragc->total_len)
    len = this_data_len;
  else
    len = fragc->total_len - fragc->offset;

  if (fragc->offset + len == fragc->total_len)
    is_last_frag = TRUE;
  else
    is_last_frag = FALSE;

  SSH_DEBUG(SSH_D_HIGHOK, ("sending fragment offset=%ld, len=%ld",
                           (long) fragc->offset, (long) len));

  /* Allocate packet for the fragment. */
  frag = ssh_interceptor_packet_alloc_and_copy_ext_data(interceptor,
                                                        fragc->pp,
                                                        this_hlen + len);
  if (frag == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("failed to allocate fragment"));
    error:
      ssh_interceptor_packet_free(fragc->pp);
      fragc->pp = NULL;
      return NULL;
    }

  /* Keep the from adapter flag across fragmentation. */
  if (fragc->pp->flags & SSH_ENGINE_P_FROMADAPTER)
    frag->flags |= SSH_ENGINE_P_FROMADAPTER;

#if defined (WITH_IPV6)
  if (frag->protocol == SSH_PROTOCOL_IP6)
    {
      unsigned char buf[SSH_IP6_EXT_FRAGMENT_HDRLEN];

      /* Copy the unfragmentable part from original packet. */
      if (!ssh_interceptor_packet_copy(fragc->pp,
                                       0,
                                       fragc->u.ipv6.fragh_offset,
                                       frag,
                                       0))
        goto error;
      /* Adjust packet length. */
      ucp = ssh_interceptor_packet_pullup(frag, SSH_IPH6_HDRLEN);
      if (!ucp)
        goto error;
      SSH_IPH6_SET_LEN(ucp, this_hlen + len - SSH_IPH6_HDRLEN);
      /* Create the fragment header and copy it to its place. */
      ssh_interceptor_packet_copyout(fragc->pp,
                                     fragc->u.ipv6.fragh_offset_prevnh,
                                     buf + SSH_IP6_EXT_FRAGMENT_OFS_NH,
                                     1);
      buf[SSH_IP6_EXT_FRAGMENT_OFS_RESERVED1] = 0;
      SSH_PUT_16BIT(buf + SSH_IP6_EXT_FRAGMENT_OFS_OFFSET,
                    (fragc->offset | (is_last_frag ? 0 : 1)));
      SSH_PUT_32BIT(buf + SSH_IP6_EXT_FRAGMENT_OFS_ID, fragc->u.ipv6.id);
      if (!ssh_interceptor_packet_copyin(frag, fragc->u.ipv6.fragh_offset,
                                         buf, SSH_IP6_EXT_FRAGMENT_HDRLEN))
        goto error;
      /* Set the prevnh field to indicate the presence of the fragment
         extension header. */
      buf[0] = SSH_IPPROTO_IPV6FRAG;
      if (!ssh_interceptor_packet_copyin(frag,
                                         fragc->u.ipv6.fragh_offset_prevnh,
                                         buf,
                                         1))
        goto error;
      /* Finally, copy the payload. */
      if (!ssh_interceptor_packet_copy(fragc->pp,
                                       fragc->u.ipv6.fragh_offset
                                         + fragc->offset,
                                       len,
                                       frag, fragc->frag_hlen))
        goto error;

      /* Update flags. */
      frag->flags |= SSH_ENGINE_P_ISFRAG;
      if (fragc->offset == 0)
        frag->flags |= SSH_ENGINE_P_FIRSTFRAG;
      else
        frag->flags &= ~SSH_ENGINE_P_FIRSTFRAG;
      if (is_last_frag)
        frag->flags |= SSH_ENGINE_P_LASTFRAG;
      else
        frag->flags &= ~SSH_ENGINE_P_LASTFRAG;
    }
  else
#endif /* WITH_IPV6 */
    {
      /* Copy packet header to the fragment buffer. */
      if (!ssh_interceptor_packet_copyin(frag, 0, fragc->u.ipv4.frag_hdr,
                                         SSH_IPH4_HDRLEN))
        {
          SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
          goto error;
        }

      /* Copy options into the packet. */
      if (!ssh_interceptor_packet_copyin(frag, SSH_IPH4_HDRLEN, this_options,
                                         this_optlen))
        {
          SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
          goto error;
        }

      /* Copy data from the original packet to the fragment data part. */
      if (!ssh_interceptor_packet_copy(fragc->pp,
                                       fragc->u.ipv4.hdrlen + fragc->offset,
                                       len, frag, this_hlen))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Copy failed, dropping packet"));
          goto error;
        }

      /* Make required changes to the packet header. */
      ucp = ssh_interceptor_packet_pullup(frag, this_hlen);
      if (ucp == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not pull up a fragment packet"));
          goto error;
        }
      /* Set new header length. */
      SSH_IPH4_SET_HLEN(ucp, (this_hlen >> 2));

      /* Compute new values for fragment offset and flag bits. */
      fragoff_orig = SSH_IPH4_FRAGOFF(ucp);
      offset_orig = (fragoff_orig & SSH_IPH4_FRAGOFF_OFFMASK) << 3;
      fragoff = fragoff_orig & SSH_IPH4_FRAGOFF_RF;
      if (fragc->offset + this_data_len < fragc->total_len ||
          (fragoff_orig & SSH_IPH4_FRAGOFF_MF))
        fragoff |= SSH_IPH4_FRAGOFF_MF;

      /* If df_on_first_fragment is set and this is the first fragment,
         set DF bit */
      if (fragc->offset == 0 && fragc->u.ipv4.df_on_first_fragment)
        fragoff |= SSH_IPH4_FRAGOFF_DF;

      /* Update fastpath's pp flags in fragments. */

      /* This is a fragment. */
      frag->flags |= SSH_ENGINE_P_ISFRAG;

      /* Is it the last fragment? */
      if (fragc->offset + this_data_len < fragc->total_len)
        frag->flags &= ~SSH_ENGINE_P_LASTFRAG;
      else
        frag->flags |= SSH_ENGINE_P_LASTFRAG;

      /* Is it the first fragment? */
      if (fragc->offset == 0)
        frag->flags |= SSH_ENGINE_P_FIRSTFRAG;
      else
        frag->flags &= ~SSH_ENGINE_P_FIRSTFRAG;

      SSH_ASSERT((fragc->offset & 7) == 0);
      SSH_IPH4_SET_FRAGOFF(ucp,
                           (fragoff | ((fragc->offset + offset_orig) >> 3)));
      SSH_IPH4_SET_LEN(ucp, this_hlen + len);
      SSH_IPH4_SET_CHECKSUM(ucp, 0);







      if (!(fragc->pp->flags & SSH_PACKET_IP4HHWCKSUM))
        {
          checksum = ssh_ip_cksum(ucp, this_hlen);
          SSH_IPH4_SET_CHECKSUM(ucp, checksum);
        }
    }

  /* Update next fragment offset. */
  fragc->offset += len;

  /* Return the fragment. */
  return frag;
}

/* Deinitializes the fragmentation context.  This basically just frees
   the original packet. */

void ssh_fastpath_fragc_uninit(SshFastpath fastpath,
                             SshFastpathFragmentContext fragc)
{
  if (fragc->pp)
    ssh_interceptor_packet_free(fragc->pp);
}
