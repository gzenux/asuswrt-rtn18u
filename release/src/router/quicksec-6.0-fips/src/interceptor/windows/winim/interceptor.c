/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of SSH IPSEC interceptor
   API functions for Windows 2000 platform.

   The description of these functions can be found at interceptor.h.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor.h"
#include "interceptor_i.h"
#include "win_ip_route.h"
#include "adapter.h"
#include "wan_interface.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE "SshInterceptor"

/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

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
  SshNdisPacket packet;
  ULONG first_buf_len = SSH_ETHERH_HDRLEN;
  SshNdisIMAdapter adapter;
  SshCpuContext cpu_ctx;
  Boolean use_one_buffer = FALSE;
  ULONG new_value;

  /* Sanity checks for arguments */
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT((ip->flags & SSH_PACKET_FROMADAPTER) !=
              (ip->flags & SSH_PACKET_FROMPROTOCOL));
  SSH_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  packet = CONTAINING_RECORD(ip, SshNdisPacketStruct, ip);

#ifdef DEBUG_LIGHT
  packet->f.flags.in_engine = 0;
#endif /* DEBUG_LIGHT */

  adapter = (SshNdisIMAdapter)packet->adapter_in;

  /* Check if adapter where the packet should be sent is
     different where the packet originated from */
  if (adapter && (adapter->ifnum == ip->ifnum_out))
    {
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

      adapter = (SshNdisIMAdapter)gen_adapter;
    }
  SSH_ASSERT(new_value > 0);

  /* Check that active adapter found and it supports the protocol */
  if (!ssh_adapter_is_enabled((SshNdisIMAdapter)adapter))
    {
      SSH_DEBUG(SSH_D_FAIL, ("active network connection not found"));
      goto free_packet;
    }

  /* Check if packet is plain IPv4 (IPv6) and then add ethernet framing */
  if (ip->protocol == SSH_PROTOCOL_IP4 || ip->protocol == SSH_PROTOCOL_IP6)
    {
      if (!ssh_wan_packet_encapsulate((SshAdapter)adapter, ip))
        {
          SSH_DEBUG(SSH_D_FAIL, ("packet framing failed"));
          goto free_packet;
        }

      /* Some dial-up drivers seem to expect to receive whole packet in one
         NDIS buffer. */
      if (ip->flags & SSH_PACKET_FROMADAPTER)
        use_one_buffer = TRUE;
    }

  /* Add the VLAN tagging, if any */
  if (packet->vlan_tag_count > 0)
    {
      if (adapter != (SshNdisIMAdapter)packet->adapter_in)
        {
          /* Engine forwards this packet to different interface. Check 
             whether this is VLAN/QoS enabled interface and reconstruct
             tagging accordingly. */

          switch (adapter->options 
                  & (NDIS_MAC_OPTION_8021Q_VLAN
                     | NDIS_MAC_OPTION_8021P_PRIORITY))
            {
            case 0:
              /* Adapter doesn't support IEEE 802.1q/p; drop VLAN tag(s). */
              packet->vlan_tag_count = 0;
              break;

            case NDIS_MAC_OPTION_8021P_PRIORITY:
              /* Adapter supports only priority (QoS) tagging. */
              packet->vlan_tags[0].vlan_id = 0;
              packet->vlan_tag_count = 1;
              break;

            default:
              /* Adapter supports also VLAN. Change the VLAN ID of the
                 first tag to the one configued to this NIC driver. */
              packet->vlan_tags[0].vlan_id = adapter->vlan_id;
              break;
            }
        }

      if (packet->vlan_tag_count)
        {
          unsigned char *vlan_tags;
          SshUInt16 i;

          vlan_tags = 
            ssh_interceptor_packet_insert(ip, SSH_ETHERH_OFS_TYPE,
                                          packet->vlan_tag_count * 4);
          if (vlan_tags == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to add VLAN tags"));
              return;
            }

          for (i = 0; i < packet->vlan_tag_count; i++)
            {
              unsigned char *tag = vlan_tags + (i * 4);

              SSH_PUT_16BIT(tag, SSH_ETHERTYPE_VLAN);
              SSH_PUT_16BIT((tag + 2), 
                            (packet->vlan_tags[i].vlan_id << 4
                            | packet->vlan_tags[i].qos));
            }
        }
    }

  NDIS_SET_PACKET_HEADER_SIZE(packet->np, SSH_ETHERH_HDRLEN);
  NDIS_SET_PACKET_STATUS(packet->np, NDIS_STATUS_SUCCESS);

  if (ip->flags & SSH_PACKET_FROMPROTOCOL)
    {
      NDIS_STATUS status;

      /* Send packet to network */
      NdisSetPacketFlags(packet->np, NDIS_FLAGS_DONT_LOOPBACK);

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
          NdisSend(&status, adapter->binding_handle, packet->np);

          if (status != NDIS_STATUS_PENDING)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Send operation completed synchronously; "
                         "packet=0x%p, status=%@",
                         ssh_ndis_status_render, status));
              ssh_interceptor_packet_free(&packet->ip);
            }
        }
    }
  else if (ip->flags & SSH_PACKET_FROMADAPTER)
    {
      /* Packet is ready now so check packet consistency */
      if (use_one_buffer)
        first_buf_len = packet->packet_len;
      else
        first_buf_len += adapter->lookahead_size;
      first_buf_len = MIN(first_buf_len, packet->packet_len);
        
      if (!ssh_packet_get_contiguous_data((SshNetDataPacket)packet, 
                                          0, first_buf_len, FALSE))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid packet"));
          goto free_packet;
        }

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
	  if (cpu_ctx->in_packet_cb)
	    {
	      ssh_net_packet_enqueue(&cpu_ctx->recv_queue[adapter->ifnum],
				     (SshNetDataPacket)packet);
	      cpu_ctx->packets_in_recv_queue = 1;
	    }
	  else if (cpu_ctx->in_route_cb)
	    {
	      ssh_net_packet_enqueue(&cpu_ctx->route_recv_queue[adapter->ifnum],
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
          packet->f.flags.in_protocol = 1;
#endif /* DEBUG_LIGHT */
          NdisMIndicateReceivePacket(adapter->handle, &packet->np, 1);
        }
    }
  else
    {
      SSH_NOTREACHED;
    }

  return;

 free_packet:
  /* Otherwise just drop the packet */
  SSH_DEBUG(SSH_D_FAIL, ("ssh_interceptor_send(): dropping packet"));
  ssh_interceptor_packet_free(&packet->ip);
}


#ifdef INTERCEPTOR_HAS_PACKET_DETACH
void ssh_interceptor_packet_detach(SshInterceptorPacket pp)
{
  SshNetDataPacket packet;
  SshInterceptor interceptor;

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

  if (packet->parent_complete_cb != NULL)
    {
      (*(packet->parent_complete_cb))(packet->parent_complete_handle,
                                      packet->parent_complete_np,
                                      packet->parent_complete_param);
  
      packet->parent_complete_cb = NULL_FNPTR;
    }

  packet->f.flags.detached = 1;
  packet->f.flags.can_not_pend = 0;
}
#endif /* INTERCEPTOR_HAS_PACKET_DETACH */

