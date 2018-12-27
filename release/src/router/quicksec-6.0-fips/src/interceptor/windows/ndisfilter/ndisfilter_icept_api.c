/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of interceptor API functions for
   Windows Vista client and Windows Server 2008 platforms.

   The description of these functions can be found at interceptor.h.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor.h"
#include "interceptor_i.h"
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#include "win_ip_route.h"
#include "wan_interface.h"
#include <netioapi.h>
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE  "SshInterceptorGlue"

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_interceptor_send()
  
  Sends packet either down to the network or up to the protocol.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_send(SshInterceptor interceptor,
                     SshInterceptorPacket ip,
                     size_t media_header_len)
{
  SshNdisFilterAdapter adapter;
  SshNdisPacket packet;
  NDIS_PORT_NUMBER port_number;
  Boolean can_not_pend = FALSE;
  ULONG ndis_flags;
  LONG new_value;
  NET_BUFFER *nb;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT((ip->flags & SSH_PACKET_FROMADAPTER) !=
             (ip->flags & SSH_PACKET_FROMPROTOCOL));
  SSH_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  packet = CONTAINING_RECORD(ip, SshNdisPacketStruct, ip);

#ifdef DEBUG_LIGHT
  packet->f.flags.in_engine = 0;
  /* Our NET_BUFFER_LIST must contain one and only one NET_BUFFER (but can
     containt several MDLs in a linked list) */
  nb = NET_BUFFER_LIST_FIRST_NB(packet->np);
  ASSERT(nb != NULL);
  ASSERT(NET_BUFFER_NEXT_NB(nb) == NULL);
#endif /* DEBUG_LIGHT */

  adapter = (SshNdisFilterAdapter)packet->adapter_in;

  if ((packet->f.flags.from_local_stack == 0)
      && (NDIS_TEST_RECEIVE_CANNOT_PEND(packet->transfer_flags)))
    can_not_pend = TRUE;

  if ((adapter) && (adapter->ifnum == ip->ifnum_out))
    {
      port_number = packet->port_number;
      ndis_flags = packet->transfer_flags;
      new_value = InterlockedIncrement(&adapter->ref_count);
      packet->adapter_out = (SshAdapter)adapter;
    }
  else
    {
      SshAdapter gen_adapter = NULL;

      if (ip->ifnum_out < SSH_INTERCEPTOR_MAX_ADAPTERS)
        {
          ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
          gen_adapter = interceptor->adapter_table[ip->ifnum_out];
          if (gen_adapter)
            {
              new_value = InterlockedIncrement(&gen_adapter->ref_count);
              packet->adapter_out = gen_adapter;
            }
          ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);
        }

      if (gen_adapter == NULL)
        goto free_packet;

      adapter = (SshNdisFilterAdapter)gen_adapter;

      /* Update NET_BUFFER_LIST's SourceHandle for forwarded packets */
      packet->np->SourceHandle = adapter->handle;

      port_number = 0;  /* Use default NDIS port number */
      ndis_flags = 0;   
    }
  SSH_ASSERT(new_value > 0);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Adapter %@: ssh_interceptor_send(ip=0x%p, media_header_len=%u)",
             ssh_adapter_id_st_render, adapter, ip, media_header_len));

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Check if packet is plain IPv4 or IPv6 packet */
  if ((ip->protocol == SSH_PROTOCOL_IP4) 
      || (ip->protocol == SSH_PROTOCOL_IP6))
    {
      switch (adapter->media)
        {
        case NdisMediumWan:
	case NdisMediumCoWan:
          /* Add media header */
          if (!ssh_wan_packet_encapsulate((SshAdapter)adapter, ip))
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Adapter %@: packet framing failed",
                         ssh_adapter_id_st_render, adapter));
              goto free_packet;
            }
          break;

        case NdisMediumWirelessWan:
          /* Update NblFlags according to the protocol type */
          NdisClearNblFlag(packet->np, NDIS_NBL_FLAGS_IS_IPV4);
          NdisClearNblFlag(packet->np, NDIS_NBL_FLAGS_IS_IPV6);
          if (ip->protocol == SSH_PROTOCOL_IP4)
	    {
	      NET_BUFFER_LIST_INFO(packet->np, NetBufferListFrameType) = 
		(PVOID)RtlUshortByteSwap(0x0800);
            NdisSetNblFlag(packet->np, NDIS_NBL_FLAGS_IS_IPV4);
	      SSH_DEBUG(SSH_D_NICETOKNOW, ("Set flags to IPv4 and FrameType"
					   " to %04x",
					   NET_BUFFER_LIST_INFO(packet->np, 
						    NetBufferListFrameType)));
	    }
          else
	    {
	      NET_BUFFER_LIST_INFO(packet->np, NetBufferListFrameType) = 
		(PVOID)RtlUshortByteSwap(0x86dd);
            NdisSetNblFlag(packet->np, NDIS_NBL_FLAGS_IS_IPV6);
	      SSH_DEBUG(SSH_D_NICETOKNOW, ("Set flags to IPv6 and FrameType"
					   " to %04x",
					   NET_BUFFER_LIST_INFO(packet->np, 
						    NetBufferListFrameType)));
	    }
          break;

        default:
          break;
        }
    }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  if (ip->flags & SSH_PACKET_FROMPROTOCOL)  
    {
      NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO cksum_info;
      NDIS_SET_SEND_FLAG(ndis_flags, NDIS_SEND_FLAGS_DISPATCH_LEVEL);

      cksum_info.Value = 
        NET_BUFFER_LIST_INFO(packet->np, TcpIpChecksumNetBufferListInfo);

      /* If the flag is set, make sure that it is set also in 
         cksum_info. */
      if (ip->flags & SSH_PACKET_IP4HHWCKSUM)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                          ("Adapter %@, packet 0x%p: "
                           "Setting HW checksum flags for IPv4",
                           ssh_adapter_id_st_render, adapter, packet));

          cksum_info.Transmit.IpHeaderChecksum = 1;
          cksum_info.Transmit.IsIPv4 = 1;
        } 
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                          ("Adapter %@, packet 0x%p: "
                           "Clearing HW checksum flags for IPv4",
                           ssh_adapter_id_st_render, adapter, packet));
          /* We are not allowed to compute IP header checksum
             in HW. */
          cksum_info.Transmit.IpHeaderChecksum = 0;
        }

      if (cksum_info.Transmit.TcpChecksum ||
          cksum_info.Transmit.UdpChecksum)
        {
          /* If the HWCKSUM flag has been cleared, we need to disable checksum
             offloads for this packet. */
          if ((ip->flags & SSH_PACKET_HWCKSUM) == 0)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                              ("Adapter %@, packet 0x%p: "
                               "Clearing HW checksum flags for TCP/UDP",
                               ssh_adapter_id_st_render, adapter, packet));

              cksum_info.Transmit.TcpChecksum = 0;
              cksum_info.Transmit.UdpChecksum = 0;
            }
        }
      
      NET_BUFFER_LIST_INFO(packet->np, TcpIpChecksumNetBufferListInfo) = 
        cksum_info.Value;
	
      if (!ssh_adapter_can_accept_send(adapter))
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: send disbled; dropping packet 0x%p",
                     ssh_adapter_id_st_render, adapter, packet));
          goto free_packet;
        }

      /* We should truncate MDL chain because some NIC drivers seem to 
         incorrectly "ignore" DataLength of the NET_BUFFER_LIST and consider
         the full MDL chain as a one Ethernet packet. */
      if (packet->f.flags.packet_copied)
        {
          SshUInt32 len_bytes;
          PMDL mdl;

          nb = NET_BUFFER_LIST_FIRST_NB(packet->np);
          mdl = NET_BUFFER_CURRENT_MDL(nb);

          len_bytes = 
            NET_BUFFER_CURRENT_MDL_OFFSET(nb) + NET_BUFFER_DATA_LENGTH(nb);

          while (mdl && len_bytes)
            {
              if (len_bytes < mdl->ByteCount)
                mdl->ByteCount = len_bytes;

              len_bytes -= mdl->ByteCount;
              NdisGetNextMdl(mdl, &mdl);
            }

          if (len_bytes != 0)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Adapter %@, packet 0x%p: "
                         "Failed to truncate MDL chain",
                         ssh_adapter_id_st_render, adapter, packet));
              goto free_packet;
            }
        }

      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];







      if (cpu_ctx->in_packet_cb 
	  || cpu_ctx->in_route_cb 
	  || cpu_ctx->in_timeout_cb)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Risk for recursive call; enqueueing packet 0x%p",
                     packet));

#ifdef DEBUG_LIGHT
          packet->f.flags.in_send_queue = 1;
#endif /* DEBUG_LIGHT */
          packet->port_number = port_number;
          packet->transfer_flags = ndis_flags;

	  /* Choose the correct queue. */
	  if (cpu_ctx->in_packet_cb)
	    {
	      ssh_net_packet_enqueue(&cpu_ctx->send_queue[adapter->ifnum],
				     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_send_queue = 1;
	    }
	  else if (cpu_ctx->in_route_cb)
	    {
	      ssh_net_packet_enqueue(&cpu_ctx->route_send_queue[adapter->ifnum],
				     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_route_send_queue = 1;
	    }
	  else if (cpu_ctx->in_timeout_cb)
	    {
	      ssh_net_packet_enqueue(
				&cpu_ctx->timeout_send_queue[adapter->ifnum],
				(SshNetDataPacket)packet);
	      cpu_ctx->packets_in_timeout_send_queue = 1;
	    }
        }
      else
        {
#ifdef DEBUG_LIGHT
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Sending packet 0x%p to underlying driver",
                     packet));

          packet->f.flags.in_miniport = 1;
#endif /* DEBUG_LIGHT */
          NdisFSendNetBufferLists(adapter->handle, 
                                  packet->np, 
                                  port_number, 
                                  ndis_flags);
        }
    }
  else if (ip->flags & SSH_PACKET_FROMADAPTER)
    {
      NDIS_SET_RECEIVE_FLAG(ndis_flags, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);

      if (!ssh_adapter_can_accept_receive(adapter))
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: receive disabled; dropping packet 0x%p",
                     ssh_adapter_id_st_render, adapter, packet));

          goto free_packet;
        }

      if (can_not_pend)
        {
          NDIS_SET_RECEIVE_FLAG(ndis_flags, NDIS_RECEIVE_FLAGS_RESOURCES);
          packet->f.flags.can_not_pend = 1;
        }

      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];







      if (cpu_ctx->in_packet_cb 
	  || cpu_ctx->in_route_cb
	  || cpu_ctx->in_timeout_cb)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Risk for recursive call; enqueueing packet 0x%p",
                     packet));

#ifdef DEBUG_LIGHT
          packet->f.flags.in_recv_queue = 1;
#endif /* DEBUG_LIGHT */

          /* Ok, handle the special case when the call path is followng:
             packet_from_protocol -> ssh_filter_send in 
             ssh_filter_process_enqueued_packets -> @adapter and adapter
             generates packet back to the QS with receive flags 
             NDIS_RECEIVE_FLAGS_RESOURCES -> ssh_filter_receive ->
             ssh_interceptor_send. In this case we need to detach the
             packet. */
          if ((can_not_pend == 1) && (packet->f.flags.detached == 0) && 
              cpu_ctx->in_queue_flush)
            ssh_interceptor_packet_detach(&packet->ip);

          packet->port_number = port_number;
          packet->transfer_flags = ndis_flags;

	  /* Choose the correct queue. */
	  if (cpu_ctx->in_packet_cb)
	    {
	      ssh_net_packet_enqueue(&cpu_ctx->recv_queue[adapter->ifnum],
				     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_recv_queue = 1;
	    }
	  else if (cpu_ctx->in_route_cb)
	    {
	      ssh_net_packet_enqueue(
                             &cpu_ctx->route_recv_queue[adapter->ifnum],
			     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_route_recv_queue = 1;
	    }
	  else if (cpu_ctx->in_timeout_cb)
	    {
	      ssh_net_packet_enqueue(
                             &cpu_ctx->timeout_recv_queue[adapter->ifnum],
			     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_timeout_recv_queue = 1;
	    }
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Indicating packet 0x%p to upper layers",
                     packet));

#ifdef DEBUG_LIGHT
          if (NDIS_TEST_RECEIVE_CANNOT_PEND(packet->transfer_flags) &&
              (packet->f.flags.packet_copied == 0))
            ssh_fatal("Packet cannot pend, its not copied and comes"
                      " from asynch call.");

          packet->f.flags.in_protocol = 1;
#endif /* DEBUG_LIGHT */
          NdisFIndicateReceiveNetBufferLists(adapter->handle,
                                             packet->np,
                                             port_number,
                                             1,
                                             ndis_flags);

          /* NDIS6: We don't receive completion indications if 'Can not pend'
             flag is set. */
          if (can_not_pend)
            {
#ifdef DEBUG_LIGHT
              packet->f.flags.in_protocol = 0;
#endif /* DEBUG_LIGHT */
              ssh_interceptor_packet_free(&packet->ip);
            }
        }
    }
  else
    {
      SSH_NOTREACHED;
    }

  return;

 free_packet:
   SSH_DEBUG(SSH_D_FAIL, 
             ("Adapter %@: ssh_interceptor_send() dropping packet %p!",
              ssh_adapter_id_st_render, adapter, packet));

   ssh_interceptor_packet_free(&packet->ip);
}


#ifdef INTERCEPTOR_HAS_PACKET_DETACH
void ssh_interceptor_packet_detach(SshInterceptorPacket pp)
{
  SshNetDataPacket packet;
  SshInterceptor interceptor;
  NET_BUFFER_LIST *parent;

  SSH_ASSERT(pp != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("ssh_interceptor_packet_detach(ip=0x%p)", pp));

  packet = CONTAINING_RECORD(pp, SshNetDataPacketStruct, ip);
  interceptor = packet->interceptor;






  /* We do not have to copy the packet if it's already done
     at some stage. */
  if (!packet->f.flags.packet_copied)
    {
      if (!ssh_packet_copy_original_data(packet))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to copy original packet data."
                                 " Cannot detach packet %p.", pp));
          return;
        }
    }

  SSH_ASSERT(packet->np != NULL);
  parent = packet->np->ParentNetBufferList;
  if (parent)
    {
      SSH_ASSERT(parent->ChildRefCount > 0);
      parent->ChildRefCount--;

      if ((parent->ChildRefCount == 0) 
           && (packet->parent_complete_cb != NULL))
        {
          (*(packet->parent_complete_cb))(packet->parent_complete_handle,
                                          packet->parent_complete_np,
                                          packet->parent_complete_param);
      
        }

      packet->np->ParentNetBufferList = NULL;
      packet->parent_complete_cb = NULL_FNPTR;
    }

  /* Clear the flag for pending, we may do it now. */
  packet->f.flags.can_not_pend = 0;
  packet->f.flags.detached = 1;
}
#endif /* INTERCEPTOR_HAS_PACKET_DETACH */

