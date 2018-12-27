/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of internal routines for
   Windows 2000 interceptor object.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor_i.h"
#include "win_ip_interface.h"
#include "kernel_timeouts.h"
#include "adapter.h"
#include "lower_edge.h"
#include "event.h"
#include "wan_interface.h"
#include <tdikrnl.h>
#include <tdiinfo.h>  

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE              "SshInterceptorInternal"

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

/*------------------------------------------------------------------------
  CONSTANTS
  ------------------------------------------------------------------------*/

/*------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  ------------------------------------------------------------------------*/

/*------------------------------------------------------------------------
  ssh_interceptor_send_to_engine()
   
  If interceptor is enabled then packets are sent
  to engine for post-processing otherwise the packet resources are freed.  
  
  Arguments:
  interceptor - interceptor object
  adpater - adapter object
  pkt_cts - packet context
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/
void
ssh_interceptor_send_to_engine(SshNdisIMInterceptor interceptor,
                               SshNdisIMAdapter adapter,
                               SshNdisPacket packet)
{
  PNDIS_PACKET pkt = packet->np;
  size_t media_header_len = SSH_ETHERH_HDRLEN;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);

  /* Remove VLAN tagging before forwarding this packet to engine. This code
     supports also stacked VLANs. The maximum amount of VLAN encapsulation
     tags is defined by SSH_VLAN_MAX_VLAN_TAGS. */
  if (packet->eth_type == SSH_ETHERTYPE_VLAN)
    {
      SshUInt16 tag_count = 0;
 
      while (packet->eth_type == SSH_ETHERTYPE_VLAN)
        {
          unsigned char temp[4];
          SshUInt16 tag;

          if (tag_count == SSH_VLAN_MAX_VLAN_TAGS)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Maximum number of stacked VLAN IDs edceeded; "
                        "dropping packet."));

              ssh_interceptor_packet_free(&packet->ip);
              return;
            }

          /* Copy next VLAN tag to packet context */
          ssh_interceptor_packet_copyout(&packet->ip, 
                                         media_header_len 
                                         + tag_count * sizeof(temp), 
                                         temp, sizeof(temp));

          tag = SSH_GET_16BIT(temp);

          packet->vlan_tags[tag_count].qos = (tag & 0x0007);
          packet->vlan_tags[tag_count].vlan_id = (tag >> 4);
          packet->eth_type = SSH_GET_16BIT(&temp[2]);

          /* If we haven't seen OID_GEN_VLAN_ID query/set (this is the case
             in Windows 2000), we need to pick and store the VLAN ID from 
             this packet. */
          if ((tag_count == 0) && (adapter->vlan_id_known == 0))
            adapter->vlan_id = packet->vlan_tags[0].vlan_id;

          tag_count++;
        }

      /* Delete VLAN tags from packet */
      if (!ssh_interceptor_packet_delete(&packet->ip,
                                         SSH_ETHERH_OFS_TYPE,
                                         tag_count * 4))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to remove VLAN tags"));
          return;
        }

      packet->vlan_tag_count = tag_count;
    }

  if (adapter->media == NdisMediumWan)
    {
      if (ssh_wan_packet_decapsulate((SshAdapter)adapter, &packet->ip))
        media_header_len = 0;
    }

  if (packet->ip.flags & SSH_PACKET_FROMADAPTER)
    {
      if (NdisGetPacketFlags(packet->np) & NDIS_FLAGS_IS_LOOPBACK_PACKET &&
          interceptor->pass_loopback == 1)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet %p had loopback flag. Passed"
                                       " it through...", 
                                       packet));
          goto pass_now;
        }

      if (interceptor->pass_promiscuous == 1 && adapter->promiscuous_mode == 1)
        {
          SshMediaHeader header;

          ssh_packet_query_media_header(packet->np, &header);
          
          if (header && adapter->media_addr_len == 6 &&
              (memcmp(header->dst, adapter->media_addr, 
                      adapter->media_addr_len) != 0) &&
              ((header->dst[0] & 0x1) == 0))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet is promiscuous, passing"
                                           " it through...", 
                                           packet));
              goto pass_now;
            }
        }
    }

  if (interceptor->net_ready
      /* Pass-through PPPoE traffic. (Our interceptor sees these packets 
         twice, another time with Ethernet+IP framing.) */
      && (packet->eth_type != SSH_ETHERTYPE_PPPOE_DISCOVERY)
      && (packet->eth_type != SSH_ETHERTYPE_PPPOE_SESSION)
      && (packet->eth_type != SSH_ETHERTYPE_8021X)
      /* Passing of IEEE 802.3 packets can be enabled in system registry
         (this feature is needed for Microsoft HCT 12.1 compliance). See 
         readme_qs.txt for details. */
#ifdef HAS_IEEE802_3_PASSTHRU
      && (!interceptor->pass_ieee802_3 || (packet->eth_type > 0x5dc))
#endif /* HAS_IEEE802_3_PASSTHRU */
     ) 
    {
#ifdef DEBUG_LIGHT
      packet->f.flags.in_engine = 1;
#endif /* DEBUG_LIGHT */
      /* Send packet to engine using the callback */
      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
      cpu_ctx->in_packet_cb = 1;
      interceptor->packet_cb(&packet->ip, interceptor->packet_cb_ctx);
      cpu_ctx->in_packet_cb = 0;
    }
  else
    {
    pass_now:
      packet->ip.ifnum_out = packet->ip.ifnum_in;
      ssh_interceptor_send((SshInterceptor)interceptor, 
                           &packet->ip, media_header_len);
    }
}


void
ssh_interceptor_flush_packet_queue(SshInterceptor gen_interceptor,
				   SshPacketQueue queue, 
				   Boolean send)
{
#define SSH_PACKET_ARRAY_SIZE  64
  SshNdisIMAdapter adapter;
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)gen_interceptor;
  PNDIS_PACKET packet_array[SSH_PACKET_ARRAY_SIZE];
  SshNdisPacket packet;
  SshUInt32 i;
  SshUInt32 packet_count;
  SshUInt32 packets_left;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Process queued packets now..."));

  if (send == TRUE)
    {
      for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
	{
	  adapter = (SshNdisIMAdapter)interceptor->adapter_table[i];
          
	  if (adapter != NULL)
	    {
	      packet = 
		(SshNdisPacket)ssh_net_packet_list_dequeue(&queue[i],
							   &packets_left);
	      while (packet)
		{
		  packet_count = 0;
		  
		  while (packet)
		    {
		      if (packet_count == SSH_PACKET_ARRAY_SIZE)
			break;
		      
#ifdef DEBUG_LIGHT
		      packet->f.flags.in_send_queue = 0;
		      packet->f.flags.in_miniport = 1;
		      packets_left--;
#endif /* DEBUG_LIGHT */
		      packet_array[packet_count] = packet->np;
		      packet_count++;
		      
		      packet = packet->next;
		    }
		  
		  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Adapter %@: sending %u NDIS_PACKET(s), "
			     "%u packet(s) remaining",
			     ssh_adapter_id_st_render, adapter, 
			     packet_count, packets_left));
		  
		  NdisSendPackets(adapter->binding_handle, 
				  packet_array, packet_count);
		}
	      
	      SSH_ASSERT(packets_left == 0);
	    }
	}
    }
  else 
    {
      for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
	{
	  adapter = (SshNdisIMAdapter)interceptor->adapter_table[i];
          
	  if (adapter != NULL)
	    {
	      packet = 
		(SshNdisPacket)ssh_net_packet_list_dequeue(&queue[i],
							   &packets_left);
	      while (packet)
		{
		  packet_count = 0;
		  
		  while (packet)
		    { 
		      if (packet_count == SSH_PACKET_ARRAY_SIZE)
			break;
		      
#ifdef DEBUG_LIGHT
		      packet->f.flags.in_recv_queue = 0;
		      packet->f.flags.in_protocol = 1;
		      packets_left--;
#endif /* DEBUG_LIGHT */
		      packet_array[packet_count] = packet->np;
		      packet_count++;
		      
		      packet = packet->next;
		    }
		  
		  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Adapter %@: indicating %u NDIS_PACKET(s) to "
			     "protocol, %u packet(s) remaining",
			     ssh_adapter_id_st_render, adapter, 
			     packet_count, packets_left));
		  
		  NdisMIndicateReceivePacket(adapter->handle, 
					     packet_array, packet_count);
		}
	      
	      SSH_ASSERT(packets_left == 0);
	    }
	}
    }
}

void
ssh_interceptor_process_enqueued_packets(SshNdisIMInterceptor interceptor, 
                                         SshCpuContext cpu_ctx)
{
  /* Return immediately if the current CPU is already executing this
     function. (This will happen e.g. if protocol stack sends a new packet
     before it returns from NdisMIndicateReceivePacket()) */
  if (cpu_ctx->in_queue_flush)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring recursive flush request"));
      return;
    }

  while (cpu_ctx->packets_in_recv_queue || cpu_ctx->packets_in_send_queue)
    {
      cpu_ctx->in_queue_flush = 1;

      if (cpu_ctx->packets_in_send_queue)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Flushing send queues..."));
          cpu_ctx->packets_in_send_queue = 0;

	  ssh_interceptor_flush_packet_queue((SshInterceptor)interceptor, 
					     cpu_ctx->send_queue, TRUE);
	}

      if (cpu_ctx->packets_in_recv_queue)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Flushing receive queues..."));
          cpu_ctx->packets_in_recv_queue = 0;

	  ssh_interceptor_flush_packet_queue((SshInterceptor)interceptor, 
					     cpu_ctx->recv_queue, FALSE);
        }

      cpu_ctx->in_queue_flush = 0;
    }
}

/*-------------------------------------------------------------------------
  TDI CLIENT CALLBACK FUNCTIONS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_tdi_pnp_power_change()
  
  Notifies that power state of networking device has changed.  
  
  Arguments:
  dev_name - networking device name
  pnp_event - power event
  context1 - system specific #1
  context2 - system specific #2
   
  Returns:
  NDIS_STATUS_SUCCESS - allways
  
  Notes:
  ------------------------------------------------------------------------*/
static NTSTATUS
ssh_tdi_pnp_power_change(PUNICODE_STRING dev_name,
                         PNET_PNP_EVENT pnp_event,
                         PTDI_PNP_CONTEXT context1,
                         PTDI_PNP_CONTEXT context2)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tdi_pnp_power_change()"));

  return (STATUS_SUCCESS);
}


static VOID
ssh_tdi_pnp_net_ready_timeout(SshInterceptor interceptor)
{
  interceptor->net_ready = TRUE;
}


/*-------------------------------------------------------------------------
  ssh_tdi_pnp_binding_change()
  
  Notifies that binding status of networking device has changed.  
  
  Arguments:
  pnp_op_code - binding operation identifier
  dev_name - networking device name
  binding_list - binding list
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/
static VOID
ssh_tdi_pnp_binding_change(TDI_PNP_OPCODE pnp_op_code,
                           PUNICODE_STRING dev_name,
                           PWSTR binding_list)
{
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)the_interceptor;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tdi_pnp_binding_change()"));

  switch (pnp_op_code)
    {
    case TDI_PNP_OP_PROVIDERREADY:
      interceptor->net_providers++;
      break;

    case TDI_PNP_OP_NETREADY:
      if (interceptor->net_providers > 0)
        {
          /* We end up here either when the system is booting up or when
             the interceptor is being installed. During the installation
             we receive TDID_PNP_OP_NETREADY immediately after we have
             registered TDI PnP handlers so we should ignore this indication
             because the interceptor is not fully initialized yet. */
          if (interceptor->init_complete)
            interceptor->net_ready = TRUE;
          else
            ssh_kernel_timeout_register(30, 0, ssh_tdi_pnp_net_ready_timeout,
                                        interceptor);
        }
      break;

    default:
      break;
    }

  /* Signal interceptor that IP config has changed */
  SSH_IP_REFRESH_REQUEST(interceptor);
}



/*-------------------------------------------------------------------------
  ssh_tdi_pnp_add_net_address()
  
  Notifies that transport protocol has added new address for some 
  network interface identified by device name.
  
  Arguments:
  net_address - network address
  dev_name - networking device name
  context - notification context
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/
static VOID
ssh_tdi_pnp_add_net_address(PTA_ADDRESS net_address,
                            PUNICODE_STRING dev_name,
                            PTDI_PNP_CONTEXT context)
{
  LIST_ENTRY *i = NULL, *list = NULL;
  NDIS_SPIN_LOCK *lock = NULL;
  SshIPDevice dev = NULL;
  SshIpAddrStruct ip_addr;

  SSH_ASSERT(net_address != NULL);
  SSH_ASSERT(the_interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tdi_pnp_add_net_address()"));

  /* Check the address type */
  if (net_address->AddressType == TDI_ADDRESS_TYPE_IP)
    {
      if (net_address->AddressLength >= sizeof(TDI_ADDRESS_IP))
        {
          PTDI_ADDRESS_IP ip4 = (PTDI_ADDRESS_IP)&net_address->Address;

          SSH_IP_DECODE(&ip_addr, &ip4->in_addr, 4); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IPv4 address[%@] addition",
                     ssh_ipaddr_render, &ip_addr));
        }
    }
#if defined (WITH_IPV6)
  else if (net_address->AddressType == TDI_ADDRESS_TYPE_IP6)
    {
      if (net_address->AddressLength >= sizeof(TDI_ADDRESS_IP6))
        {
          PTDI_ADDRESS_IP6 ip6 = (PTDI_ADDRESS_IP6)&net_address->Address;

          SSH_IP_DECODE(&ip_addr, &ip6->sin6_addr, 16); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IPv6 address[%@] addition",
                     ssh_ipaddr_render, &ip_addr));
        }
    }
#endif /* WITH_IPV6 */
  else
    {
      return;
    }

  /* Signal interceptor that IP config has changed */
  SSH_IP_REFRESH_REQUEST(the_interceptor);
}


/*-------------------------------------------------------------------------
  ssh_tdi_pnp_del_net_address()
  
  Notifies that transport protocol has removed network address of given 
  interface.
  
  Arguments:
  net_address - network address,
  device_name - networking device name,
  context - notification context.
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/
static VOID
ssh_tdi_pnp_del_net_address(PTA_ADDRESS net_address,
                            PUNICODE_STRING dev_name,
                            PTDI_PNP_CONTEXT context)
{
  LIST_ENTRY *i = NULL, *list = NULL;
  NDIS_SPIN_LOCK *lock = NULL;
  SshIPDevice dev = NULL;
  SshIpAddrStruct ip_addr;

  SSH_ASSERT(net_address != NULL);
  SSH_ASSERT(the_interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_tdi_pnp_del_net_address()"));

  /* Check the address type */
  if (net_address->AddressType == TDI_ADDRESS_TYPE_IP)
    {
      if (net_address->AddressLength >= sizeof(TDI_ADDRESS_IP))
        {
          PTDI_ADDRESS_IP ip4 = (PTDI_ADDRESS_IP)&net_address->Address;

          SSH_IP_DECODE(&ip_addr, &ip4->in_addr, 4); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IPv4 address[%@] removal",
                     ssh_ipaddr_render, &ip_addr));
        }
    }
  else if (net_address->AddressType == TDI_ADDRESS_TYPE_IP6)
    {
      if (net_address->AddressLength >= sizeof(TDI_ADDRESS_IP6))
        {
          PTDI_ADDRESS_IP6 ip6 = (PTDI_ADDRESS_IP6)&net_address->Address;

          SSH_IP_DECODE(&ip_addr, &ip6->sin6_addr, 16); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IPv6 address[%@] removal",
                     ssh_ipaddr_render, &ip_addr));
        }
    }
  else
    {
      return;
    }

  /* Signal interceptor that IP config has changed */
  SSH_IP_REFRESH_REQUEST(the_interceptor);
}

/*-------------------------------------------------------------------------
  ssh_interceptor_register_stack_notifications()
  
  Registers some callbacks with IP protocol stack so that we get 
  notifications from some transport protocol specific events.
  
  Arguments:
  interceptor - SshInterceptor object
  enable - register/deregister flag
  
  Returns:
  NDIS_STATUS_SUCCESS - operation succeeded
  NDIS_STATUS_FAILURE - otherwise

  Notes:
  ------------------------------------------------------------------------*/
NDIS_STATUS
ssh_interceptor_register_stack_notifications(SshNdisIMInterceptor interceptor,
                                             BOOLEAN enable)
{
  NTSTATUS status = STATUS_SUCCESS;
  TDI_CLIENT_INTERFACE_INFO tdi_info;

  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_register_with_tdi()"));

  if (enable == TRUE && interceptor->tdi_handle == NULL)
    {
      NdisZeroMemory(&tdi_info, sizeof(tdi_info));

      tdi_info.MajorTdiVersion = TDI_CURRENT_MAJOR_VERSION;
      tdi_info.MinorTdiVersion = TDI_CURRENT_MINOR_VERSION;
      tdi_info.TdiVersion = TDI_CURRENT_VERSION;
      tdi_info.ClientName = ssh_interceptor_service_name;

      /* Init and then register the handlers */
      tdi_info.PnPPowerHandler = ssh_tdi_pnp_power_change;
      tdi_info.BindingHandler = ssh_tdi_pnp_binding_change;
      tdi_info.AddAddressHandlerV2 = ssh_tdi_pnp_add_net_address;
      tdi_info.DelAddressHandlerV2 = ssh_tdi_pnp_del_net_address;

      status = TdiRegisterPnPHandlers(&tdi_info,
                                      sizeof(tdi_info),
                                      &interceptor->tdi_handle);

      if (status != STATUS_SUCCESS)
        {
          status = NDIS_STATUS_FAILURE;
          interceptor->tdi_handle = NULL;
          SSH_DEBUG(SSH_D_ERROR, ("  - failed!"));
        }
    }

  if (enable == FALSE && interceptor->tdi_handle != NULL)
    {
      TdiDeregisterPnPHandlers(interceptor->tdi_handle);
      interceptor->tdi_handle = NULL;
      status = NDIS_STATUS_SUCCESS;
    }

  return (status);
}


Boolean
ssh_interceptor_is_supported_os_version(SshOsVersion os)
{
  switch (os)
    {
    case SSH_OS_VERSION_W2K:
    case SSH_OS_VERSION_WXP:
    case SSH_OS_VERSION_S2003:
      return TRUE;

    default:
      return FALSE;
    }
}

