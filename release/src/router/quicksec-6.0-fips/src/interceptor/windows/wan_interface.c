/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for handling SSH WAN Interface specific tasks (parses status
   indications and decapsulates/encapsulates WAN packets).
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "wan_interface.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorWANInterface"


/** Macro for max. */
#define	SSH_MAX(a,b)	(((a) > (b)) ? (a) : (b))

/* Offsets for parsing ProtocolBuffer byte array to retrieve the
   network address information for WAN connections */
#if defined(NDIS60)
/* Windows Vista */
#define SSH_PPP_IPV4_LUID_OFFSET              24
#define SSH_PPP_IPV4_SRC_ADDR_OFFSET          584
#define SSH_PPP_IPV4_DST_ADDR_OFFSET          592
#define SSH_PPP_IPV4_PROTOCOL_BUFF_MIN_SIZE   596
#else
/* Windows 2K/XP/2K3 */
#define SSH_PPP_IPV4_SRC_ADDR_OFFSET          8
#define SSH_PPP_IPV4_DST_ADDR_OFFSET          16
#define SSH_PPP_IPV4_PROTOCOL_BUFF_MIN_SIZE   20
#endif /* NDIS60 */

#if defined(WITH_IPV6)
#if defined(NDIS60)
/* Windows Vista */
#define SSH_PPP_IPV6_LUID_OFFSET              24



#define SSH_PPP_IPV6_SRC_ADDR_OFFSET          584
#define SSH_PPP_IPV6_DST_ADDR_OFFSET          616
#define SSH_PPP_IPV6_PROTOCOL_BUFF_MIN_SIZE   636
#else



#define SSH_PPP_IPV6_SRC_ADDR_OFFSET          8
#define SSH_PPP_IPV6_DST_ADDR_OFFSET          16
#define SSH_PPP_IPV6_PROTOCOL_BUFF_MIN_SIZE   20
#endif /* NDIS60 */
#endif /* WITH_IPV6 */


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  Checks whether a specific WAN connection is open.
  --------------------------------------------------------------------------*/
BOOLEAN
ssh_adapter_wan_line_is_open(SshAdapter adapter, 
                             PUCHAR remote_address,
                             PUCHAR local_address)
{
  SshWanInterface wi = NULL;
  LIST_ENTRY *i = NULL;
  BOOLEAN found = FALSE;

  SSH_PRECOND(adapter != NULL);
  SSH_PRECOND(remote_address != NULL);

  /* Check the list */
  ssh_kernel_rw_mutex_lock_read(&adapter->wan_if_lock);
  for (i = adapter->wan_if.Flink; i != &adapter->wan_if; i = i->Flink)
    {
      wi = CONTAINING_RECORD(i, SshWanInterfaceStruct, link);

      if (RtlEqualMemory(remote_address, wi->remote.phys_addr, 
                         SSH_ETHERH_ADDRLEN)
          && RtlEqualMemory(local_address, wi->local.phys_addr, 
                            SSH_ETHERH_ADDRLEN))
        {
          found = TRUE;
          break;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&adapter->wan_if_lock);

  return (found);
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

void
ssh_wan_line_up(SshAdapter adapter,
                PNDIS_WAN_LINE_UP line_up_ind)
{
  SshWanInterface wi;
#if defined(NDIS60)
  SshUInt64 *luid;
#endif /* NDIS60 */

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter(%d): %s, e[s(%@) - d(%@)], "
             "p[0x%04X], mtu[%d], speed[%d b/s]", 
             adapter->ifnum, 
             "wan[UP]",
             ssh_etheraddr_render, line_up_ind->LocalAddress,
             ssh_etheraddr_render, line_up_ind->RemoteAddress,
             line_up_ind->ProtocolType,
             line_up_ind->MaximumTotalSize,
             line_up_ind->LinkSpeed * 100)); 

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                    ("ProtocolBuffer: "),
                    line_up_ind->ProtocolBuffer, 
                    line_up_ind->ProtocolBufferLength);

  /* Ignore line up indications having zero MTU (link is going down) */
  if (line_up_ind->MaximumTotalSize == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter(%d): ignoring wan[UP] indication (MTU = 0)"));
      return;
    }

  /* Check whether the corresponding interface already exist */
  if (ssh_adapter_wan_line_is_open(adapter, 
                                   line_up_ind->RemoteAddress, 
                                   line_up_ind->LocalAddress))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter(%d): %s, e[s(%@) - d(%@)] already open",
                 adapter->ifnum,
                 "wan[UP]",
                 ssh_etheraddr_render, line_up_ind->LocalAddress,
                 ssh_etheraddr_render, line_up_ind->RemoteAddress)); 
      return;
    }

  /* Check the size of ProtocolBuffer */
  if (((line_up_ind->ProtocolType == SSH_ETHERTYPE_IP)
       && (line_up_ind->ProtocolBufferLength 
             < SSH_PPP_IPV4_PROTOCOL_BUFF_MIN_SIZE))
#if defined(WITH_IPV6)
      || ((line_up_ind->ProtocolType == SSH_ETHERTYPE_IPv6)
          && (line_up_ind->ProtocolBufferLength 
                < SSH_PPP_IPV6_PROTOCOL_BUFF_MIN_SIZE))
#endif /* WITH_IPV6 */
     )
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter(%d) %s, e[s(%@) - d(%@)]: Too short ProtocolBuffer",
                 adapter->ifnum,
                 "wan[UP]",
                 ssh_etheraddr_render, line_up_ind->LocalAddress,
                 ssh_etheraddr_render, line_up_ind->RemoteAddress)); 
      return;
    }

  /* Create new WAN interface entry */
  if ((wi = ssh_calloc(1, sizeof(*wi))) == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to create a new WAN interface object"));
      return;
    }

  /* Set IF number, pseudo physical addresses */
  wi->link_mtu = line_up_ind->MaximumTotalSize;
  wi->local.phys_addr_len = SSH_ETHERH_ADDRLEN;
  wi->remote.phys_addr_len = SSH_ETHERH_ADDRLEN;
  RtlCopyMemory(wi->local.phys_addr, 
                line_up_ind->LocalAddress, SSH_ETHERH_ADDRLEN);
  RtlCopyMemory(wi->remote.phys_addr, 
                line_up_ind->RemoteAddress, SSH_ETHERH_ADDRLEN);

  /* Set local and remote IP addresses */
  if (line_up_ind->ProtocolType == SSH_ETHERTYPE_IP)
    {
      SSH_IP4_DECODE(&wi->local.ip_addr,
        (line_up_ind->ProtocolBuffer + SSH_PPP_IPV4_SRC_ADDR_OFFSET));
      SSH_IP4_DECODE(&wi->remote.ip_addr,
        (line_up_ind->ProtocolBuffer + SSH_PPP_IPV4_DST_ADDR_OFFSET));
#if defined(NDIS60)
      luid = 
        (SshUInt64 *)&(line_up_ind->ProtocolBuffer[SSH_PPP_IPV4_LUID_OFFSET]);
      wi->luid = *luid;
#endif /* NDIS60 */
    }
#if defined(WITH_IPV6)
  else if (line_up_ind->ProtocolType == SSH_ETHERTYPE_IPv6)
    {
      SSH_IP6_DECODE(&wi->local.ip_addr,
        (line_up_ind->ProtocolBuffer + SSH_PPP_IPV6_SRC_ADDR_OFFSET));
      SSH_IP6_DECODE(&wi->remote.ip_addr,
        (line_up_ind->ProtocolBuffer + SSH_PPP_IPV6_DST_ADDR_OFFSET));
#if defined(NDIS60)
      luid = 
        (SshUInt64 *)&(line_up_ind->ProtocolBuffer[SSH_PPP_IPV6_LUID_OFFSET]);
      wi->luid = *luid;
#endif /* NDIS60 */
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
        ("Unidentified protocol type specified in WAN line up indication"));
    }

  ssh_kernel_rw_mutex_lock_write(&adapter->wan_if_lock);
  wi->ifnum = adapter->wan_if_cnt;
  adapter->wan_if_cnt++;
  InitializeListHead(&wi->link);
  InsertTailList(&adapter->wan_if, &wi->link);
  ssh_kernel_rw_mutex_unlock_write(&adapter->wan_if_lock);

  SSH_IP_FORCE_REFRESH_REQUEST(adapter->interceptor,
                               SSH_IP_REFRESH_ALL);
}



void
ssh_wan_line_down(SshAdapter adapter,
                  PNDIS_WAN_LINE_DOWN line_down_ind)
{
  PLIST_ENTRY entry;
  PLIST_ENTRY next;
  SshWanInterface wi = NULL;


  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter(%d): %s, e[s(%@) - d(%@)]",
             adapter->ifnum,
             "wan[DOWN]",
             ssh_etheraddr_render, line_down_ind->LocalAddress,
             ssh_etheraddr_render, line_down_ind->RemoteAddress));

  /* Remove corresponding WAN interface from the list */
  ssh_kernel_rw_mutex_lock_write(&adapter->wan_if_lock);
  for (entry = adapter->wan_if.Flink; entry != &adapter->wan_if; entry = next)
    {
      next = entry->Flink;
      wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link);

      if (RtlEqualMemory(line_down_ind->RemoteAddress, 
                         wi->remote.phys_addr, SSH_ETHERH_ADDRLEN)
          && RtlEqualMemory(line_down_ind->LocalAddress, 
                            wi->local.phys_addr, SSH_ETHERH_ADDRLEN))
        {
          RemoveEntryList(entry);
          adapter->wan_if_cnt--;
          break;
        }

      wi = NULL;
    }
  ssh_kernel_rw_mutex_unlock_write(&adapter->wan_if_lock);

  if (wi != NULL)
    ssh_free(wi);
  else
    SSH_DEBUG(SSH_D_FAIL, ("Corresponding WAN Interface not found"));
}


Boolean
ssh_wan_packet_decapsulate(SshAdapter adapter,
                           SshInterceptorPacket pp)
{
  char ehdr[SSH_ETHERH_HDRLEN];
  SshUInt16 eth_protocol;
  PLIST_ENTRY entry;
  SshNdisPacket pkt_ctx;

  pkt_ctx = CONTAINING_RECORD(pp, SshNdisPacketStruct, ip);

  ssh_interceptor_packet_copyout(pp, 0, ehdr, SSH_ETHERH_HDRLEN);

  /* Determine protocol type */
  eth_protocol = SSH_GET_16BIT((ehdr + SSH_ETHERH_OFS_TYPE));
  if (eth_protocol == SSH_ETHERTYPE_IP)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Decapsulating IPv4 WAN packet"));
      pp->protocol = SSH_PROTOCOL_IP4;
    }
#if defined(WITH_IPV6)
  else if (eth_protocol == SSH_ETHERTYPE_IPv6)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Decapsulating IPv6 WAN packet"));
      pp->protocol = SSH_PROTOCOL_IP6;        
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Not decapsulating non-IP WAN packet"));
      return FALSE;
    }

  /* Remove the Ethernet header */
  ssh_interceptor_packet_delete(pp, 0, SSH_ETHERH_HDRLEN);

  /* Determine the WAN IF for the packet */
  ssh_kernel_rw_mutex_lock_read(&adapter->wan_if_lock);
  for (entry = adapter->wan_if.Flink; 
       entry != &adapter->wan_if; entry = entry->Flink)
    {
      SshWanInterface wi;

      wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link);

      /* Outgoing packet */
      if ((pp->flags & SSH_PACKET_FROMPROTOCOL)
          && RtlEqualMemory(&ehdr[SSH_ETHERH_OFS_DST], 
                            wi->remote.phys_addr, SSH_ETHERH_ADDRLEN)
          && RtlEqualMemory(&ehdr[SSH_ETHERH_OFS_SRC], 
                            wi->local.phys_addr, SSH_ETHERH_ADDRLEN))
        {
          pkt_ctx->orig_wan_ifnum = wi->ifnum;
          break;
        }

      /* Incoming packet */
      if ((pp->flags & SSH_PACKET_FROMADAPTER)
          && RtlEqualMemory(&ehdr[SSH_ETHERH_OFS_SRC], 
                            wi->remote.phys_addr, SSH_ETHERH_ADDRLEN)
          && RtlEqualMemory(&ehdr[SSH_ETHERH_OFS_DST], 
                            wi->local.phys_addr, SSH_ETHERH_ADDRLEN))
        {
          pkt_ctx->orig_wan_ifnum = wi->ifnum;
          break;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&adapter->wan_if_lock);

  return TRUE;
}


Boolean
ssh_wan_packet_encapsulate(SshAdapter adapter, 
                           SshInterceptorPacket pp)
{
  SshIpAddrStruct src, dst;
  SshWanInterface wi = NULL;
  char src_buf[SSH_MAX(SSH_ETHERH_HDRLEN, SSH_IP_ADDR_SIZE)]; 
  char dst_buf[SSH_MAX(SSH_ETHERH_HDRLEN, SSH_IP_ADDR_SIZE)];
  char *media_hdr = NULL;
  ULONG src_offset = SSH_ETHERH_HDRLEN; 
  ULONG dst_offset = SSH_ETHERH_HDRLEN; 
  ULONG addr_len = 0;
  PLIST_ENTRY entry;
  SshNdisPacket pkt_ctx;

  pkt_ctx = CONTAINING_RECORD(pp, SshNdisPacketStruct, ip);

  SSH_PRECOND(adapter != NULL);
  SSH_PRECOND(pp != NULL);
  SSH_PRECOND(adapter->media == NdisMediumWan ||
	      adapter->media == NdisMediumCoWan);

  /* Sanity checks */
  if (adapter->wan_if_cnt == 0)
    {
      /* Adapter is not WAN or no WAN connections exist */
      return (FALSE);
    }

  /* Insert space for media header */
  media_hdr = ssh_interceptor_packet_insert(pp, 0, SSH_ETHERH_HDRLEN);
  if (media_hdr == NULL)
    {
      return(FALSE);
    }

  /* Examine the media header contents */ 

  /* Protocol type: The packet must be either IPv4 or IPv6 packet */
  if (pp->protocol == SSH_PROTOCOL_IP4)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Encapsulating IPv4 WAN packet"));
      /* Set the protocol type into media header */
      SSH_PUT_16BIT((media_hdr + SSH_ETHERH_OFS_TYPE), SSH_ETHERTYPE_IP);
      /* Calc the source and destination IPv4 address offsets */
      src_offset += SSH_IPH4_OFS_SRC;
      dst_offset += SSH_IPH4_OFS_DST;
      addr_len = SSH_IPH4_ADDRLEN;
    }
#if defined(WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Encapsulating IPv6 WAN packet"));
      /* Set the protocol type into media header */
      SSH_PUT_16BIT((media_hdr + SSH_ETHERH_OFS_TYPE), SSH_ETHERTYPE_IPv6);
      /* Calc the source and destination IPv6 address offsets */
      src_offset += SSH_IPH6_OFS_SRC;
      dst_offset += SSH_IPH6_OFS_DST;
      addr_len = SSH_IPH6_ADDRLEN;
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported protocol"));
      return FALSE;
    }

  ssh_interceptor_packet_copyout(pp, dst_offset, dst_buf, addr_len);
  ssh_interceptor_packet_copyout(pp, src_offset, src_buf, addr_len);

  SSH_IP_DECODE(&dst, dst_buf, addr_len);
  SSH_IP_DECODE(&src, src_buf, addr_len);

  /* Try to find the right WAN connection for packet */ 
  ssh_kernel_rw_mutex_lock_read(&adapter->wan_if_lock); 
  if (adapter->wan_if_cnt == 1)
    {
      entry = adapter->wan_if.Flink;
      /* (1) Only one WAN connection exist so use it */
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("WAN: Using the one and only IF available"));

      wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link);
      goto wi_found;
    }

  /* Multiple open WAN connections exist - difficult case */

  /* (2) We read the source and destination IP address from packet and 
  then use them as search key when trying to find the corresponding WAN
  connection from our list. */
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("WAN: Using packet's IP addresses to find the right IF")); 

  for (entry = adapter->wan_if.Flink;
       entry != &adapter->wan_if; entry = entry->Flink)
    {
      wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link);
/*
      if (!SSH_IP_EQUAL(&wi->local.ip_addr, &src) &&
          !SSH_IP_EQUAL(&wi->local.ip_addr, &dst) &&
          !SSH_IP_EQUAL(&wi->remote.ip_addr, &src) &&
          !SSH_IP_EQUAL(&wi->remote.ip_addr, &dst))
        {
        wi = NULL;
        continue;
        }
*/
      if (((pp->flags & SSH_PACKET_FROMPROTOCOL) &&
           SSH_IP_EQUAL(&wi->local.ip_addr, &src)) ||
          ((pp->flags & SSH_PACKET_FROMADAPTER) &&
           SSH_IP_EQUAL(&wi->local.ip_addr, &dst)))
        {
          goto wi_found;
        }
    }

  /* No IP address match found so packet is forwarded into WAN IF.
     How-to we know which interface to select ??????????????      
     WE CANNOT ASSOCIATE THE RIGHT MEDIA HEADER INTO PACKET IN THIS CASE */

  /* (3) Try to use WAN connection where the packet originated from ? */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("WAN: Using original IF"));

  for (entry = adapter->wan_if.Flink;
       entry != &adapter->wan_if; entry = entry->Flink)
    {
      wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link);
      if (pkt_ctx->orig_wan_ifnum == wi->ifnum)
        {
          goto wi_found;
        }
    }

  /* The packet is originated from LAN IF or packet is allocated by 
     the engine */

  /* (4) Last effort: Use the 1st WAN interface from the list */
  entry = adapter->wan_if.Flink;

  wi = CONTAINING_RECORD(entry, SshWanInterfaceStruct, link); 

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("WAN: Using 1st IF from the list (unreliable)")); 

 wi_found:
  if (pp->flags & SSH_PACKET_FROMPROTOCOL)
    {
      /* Outgoing packet */
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("adapter(%d-%d)::%s(E(dst[%@] src[%@]):IP(dst[%@] src[%@]):"
                 "pkt_if_in[%d] pkt_if_out[%d]) framing OK", 
                 adapter->ifnum,
                 wi->ifnum,
                 "outgoing packet",
                 ssh_etheraddr_render, wi->remote.phys_addr,
                 ssh_etheraddr_render, wi->local.phys_addr,
                 ssh_ipaddr_render, &dst,
                 ssh_ipaddr_render, &src,
                 pp->ifnum_in, pp->ifnum_out));

      RtlCopyMemory(media_hdr + SSH_ETHERH_OFS_DST, 
                    wi->remote.phys_addr, SSH_ETHERH_ADDRLEN);

      RtlCopyMemory(media_hdr + SSH_ETHERH_OFS_SRC, 
                    wi->local.phys_addr, SSH_ETHERH_ADDRLEN);
    }
  else if (pp->flags & SSH_PACKET_FROMADAPTER)
    {
      /* Incoming packet */
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("adapter(%d-%d)::%s(E(dst[%@] src[%@]):IP(dst[%@] src[%@]):"
                 "pkt_if_in[%d] pkt_if_out[%d]) framing OK",
                 adapter->ifnum,
                 wi->ifnum,
                 "incoming packet",
                 ssh_etheraddr_render, wi->local.phys_addr,
                 ssh_etheraddr_render, wi->remote.phys_addr,
                 ssh_ipaddr_render, &dst,
                 ssh_ipaddr_render, &src,
                 pp->ifnum_in, pp->ifnum_out));

      RtlCopyMemory(media_hdr + SSH_ETHERH_OFS_DST, 
                    wi->local.phys_addr, SSH_ETHERH_ADDRLEN);

      RtlCopyMemory(media_hdr + SSH_ETHERH_OFS_SRC, 
                    wi->remote.phys_addr, SSH_ETHERH_ADDRLEN);
    }
  ssh_kernel_rw_mutex_unlock_read(&adapter->wan_if_lock); 

  return (TRUE);
}
