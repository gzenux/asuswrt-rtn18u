/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "virtual_adapter.h"
#include "virtual_adapter_internal.h"
#include "sshinet.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

#define SSH_DEBUG_MODULE "SshVirtualAdapterMisc"

/* Engine-side code that MUST NOT be included in interceptor unless
   the interceptor happens to contain engine. */

typedef enum {
  SSH_VA_PACKET_ARP,
  SSH_VA_PACKET_DHCP,
  SSH_VA_PACKET_OTHER,
  SSH_VA_PACKET_ERROR
} SshVaPacketType;

/************************* SshEngineVirtualAdapterContext  *******************/

Boolean
ssh_virtual_adapter_context_update(void *adapter_context,
                                   SshVirtualAdapterParams params,
                                   SshIpAddr dhcp_client_ip,
                                   const unsigned char *dhcp_option_data,
                                   size_t dhcp_option_data_len)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Updated context %p", adapter_context));

  return TRUE;
}

/* Constructor for virtual adapter context. */
void *ssh_virtual_adapter_context_create(SshInterceptor interceptor,
                                         SshInterceptorIfnum adapter_ifnum,
                                         const unsigned char *adapter_name)
{
  SshEngineVirtualAdapterContext adapter_context = NULL;
  adapter_context = ssh_calloc(1, sizeof(*adapter_context));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Created context %p", adapter_context));
  return adapter_context;
}

/* Destructor for virtual adapter context. */
void
ssh_virtual_adapter_context_destroy(void *context)
{
  SshEngineVirtualAdapterContext adapter_context =
    (SshEngineVirtualAdapterContext) context;

  if (adapter_context == NULL)
    return;

  ssh_free(adapter_context);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroyed context %p", adapter_context));
}


/******************************* Init / Uninit *******************************/

static void
ssh_virtual_adapter_attach_cb(SshVirtualAdapterError error,
                              SshInterceptorIfnum adapter_ifnum,
                              const unsigned char *adapter_name,
                              SshVirtualAdapterState state,
                              void *adapter_context,
                              void *context)
{
  if (error != SSH_VIRTUAL_ADAPTER_ERROR_OK)
    SSH_DEBUG(SSH_D_ERROR,
              ("Could not attach virtual adapter %d [%s] to engine",
               (int) adapter_ifnum, adapter_name));
  else
    SSH_DEBUG(SSH_D_MIDOK, ("Virtual adapter %d [%s] attached to engine",
                            (int) adapter_ifnum, adapter_name));
}

static void
ssh_virtual_adapter_init_status_cb(SshVirtualAdapterError error,
                                   SshInterceptorIfnum adapter_ifnum,
                                   const unsigned char *adapter_name,
                                   SshVirtualAdapterState state,
                                   void *adapter_context,
                                   void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK
      || error == SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE)
    {
      SshEngineVirtualAdapterContext adapter_ctx =
        ssh_virtual_adapter_context_create(interceptor,
                                           adapter_ifnum, adapter_name);
      if (adapter_ctx != NULL)
        ssh_virtual_adapter_attach(interceptor,
                                   adapter_ifnum,
                                   ssh_virtual_adapter_packet_callback,
                                   ssh_virtual_adapter_context_destroy,
                                   adapter_ctx,
                                   ssh_virtual_adapter_attach_cb,
                                   interceptor);
      else
        SSH_DEBUG(SSH_D_ERROR,
                  ("Could not allocate context for virtual adapter %d [%s]",
                   (int) adapter_ifnum, adapter_name));
    }
  else if (error != SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT)
    SSH_DEBUG(SSH_D_ERROR,
              ("Could not get virtual adapters from interceptor"));
}

/* Attaches all virtual adapters to engine. */
SshVirtualAdapterError ssh_virtual_adapter_init(SshInterceptor interceptor)
{
#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  /* Attach all virtual adapters to engine. */
  ssh_virtual_adapter_get_status(interceptor,
                                 SSH_INTERCEPTOR_INVALID_IFNUM,
                                 ssh_virtual_adapter_init_status_cb,
                                 interceptor);
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  return SSH_VIRTUAL_ADAPTER_ERROR_OK;
}


/* Detaches all virtual adapters from the engine. */
SshVirtualAdapterError ssh_virtual_adapter_uninit(SshInterceptor interceptor)
{
#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_detach_all(interceptor);
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  return SSH_VIRTUAL_ADAPTER_ERROR_OK;
}


/************************* Global packet callback ****************************/

/* Utility function for recognizing ARP packets */
static SshVaPacketType
ssh_virtual_adapter_packet_type(SshInterceptorPacket pp)
{
  size_t packet_len, ofs=0;
  unsigned char *ether_hdr;
  int ethertype;

  packet_len = ssh_interceptor_packet_len(pp);

  if (pp->protocol == SSH_PROTOCOL_ETHERNET)
    {
      if (packet_len < SSH_ETHERH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Ethernet packet too short for ethernet header: len=%d",
                     packet_len));
          return SSH_VA_PACKET_ERROR;
        }
      ether_hdr = ssh_interceptor_packet_pullup(pp, SSH_ETHERH_HDRLEN);
      if (!ether_hdr)
        {
          SSH_DEBUG(SSH_D_ERROR, ("pullup error."));
          return SSH_VA_PACKET_ERROR;
        }
      ethertype = SSH_GET_16BIT(ether_hdr + SSH_ETHERH_OFS_TYPE);
      if (ethertype == SSH_ETHERTYPE_ARP)
        return SSH_VA_PACKET_ARP;
      if (ethertype == SSH_ETHERTYPE_IP)
        {
          /* Peek inside the header */
          ofs = SSH_ETHERH_HDRLEN;
          goto check_ip4;
        }
#if defined (WITH_IPV6)
      else if(ethertype == SSH_ETHERTYPE_IPv6)
        {
          /* Peek inside the header */
          ofs = SSH_ETHERH_HDRLEN;
          goto check_ip6;
        }
#endif /* WITH_IPV6 */
    }
  else if (pp->protocol == SSH_PROTOCOL_IP4)
    {
      size_t desired_hlen;
      unsigned char *ip_hdr, *udp_hdr;
      SshUInt16 srcport, dstport, want_srcport, want_dstport;

    check_ip4:
      desired_hlen = SSH_IPH4_HDRLEN + SSH_UDP_HEADER_LEN;
      if (packet_len  < (ofs + desired_hlen))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("too short IP packet."));
          return SSH_VA_PACKET_ERROR;
        }
      ip_hdr = ssh_interceptor_packet_pullup(pp, ofs+desired_hlen);
      if (!ip_hdr)
        {
          SSH_DEBUG(SSH_D_ERROR, ("pullup error."));
          return SSH_VA_PACKET_ERROR;
        }
      ip_hdr += ofs;
      /* Finally, we happen to have IP packet available */
      if (SSH_IPH4_HLEN(ip_hdr) != (SSH_IPH4_HDRLEN / 4))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IP options - not proper packet."));
          return SSH_VA_PACKET_ERROR;
        }
      if (SSH_IPH4_PROTO(ip_hdr) != SSH_IPPROTO_UDP)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("wrong protocol."));
          return SSH_VA_PACKET_OTHER;
        }
      udp_hdr = ip_hdr + SSH_IPH4_HDRLEN;
      srcport = SSH_UDPH_SRCPORT(udp_hdr);
      dstport = SSH_UDPH_DSTPORT(udp_hdr);
      want_srcport = 68;
      want_dstport = 67;
      if (srcport != want_srcport || dstport != want_dstport)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("diff. ports (%d!=%d || %d!=%d).",
                                       srcport,
                                       want_srcport,
                                       dstport,
                                       want_dstport));
          return SSH_VA_PACKET_OTHER;
        }
      SSH_DEBUG(SSH_D_NICETOKNOW, ("DHCP packet matched."));
      return SSH_VA_PACKET_DHCP;
    }
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      size_t desired_hlen;
      unsigned char *ip6_hdr, *icmp_hdr;
      SshUInt8 nh, type;

    check_ip6:
      desired_hlen = SSH_IPH6_HDRLEN + SSH_ICMP6H_HDRLEN;
      if (packet_len  < (ofs + desired_hlen))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("too short IPv6 packet."));
          return SSH_VA_PACKET_ERROR;
        }
      ip6_hdr = ssh_interceptor_packet_pullup(pp, ofs+desired_hlen);
      if (!ip6_hdr)
        {
          SSH_DEBUG(SSH_D_ERROR, ("pullup error."));
          return SSH_VA_PACKET_ERROR;
        }
      ip6_hdr += ofs;
      /* Finally, we happen to have IPv6 packet available */
      nh = SSH_IPH6_NH(ip6_hdr);
      if (nh != SSH_IPPROTO_IPV6ICMP)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("IPv6 nh %d", nh));
          return SSH_VA_PACKET_OTHER;
        }

      icmp_hdr = ip6_hdr + SSH_IPH6_HDRLEN;
      type = SSH_ICMP6H_TYPE(icmp_hdr);
      if (type != SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("ICMPv6 type %d", type));
          return SSH_VA_PACKET_OTHER;
        }
      SSH_DEBUG(SSH_D_NICETOKNOW, ("ICMPv6 neighbor solicitation matched."));
      return SSH_VA_PACKET_ARP;
    }
#endif /* WITH_IPV6 */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("other packet."));
  return SSH_VA_PACKET_OTHER;
}

/* Wrapper callback that provides the functionality of calling for
   ARP handling code, or later for some other purposes. */
void
ssh_virtual_adapter_packet_callback(SshInterceptor interceptor,
                                    SshInterceptorPacket pp,
                                    void *adapter_context)
{
  switch (ssh_virtual_adapter_packet_type(pp))
    {
    case SSH_VA_PACKET_ARP:
      ssh_virtual_adapter_arp_packet_callback(interceptor,
                                              pp,
                                              adapter_context);
      return;
    case SSH_VA_PACKET_DHCP:
    case SSH_VA_PACKET_OTHER:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("unhandled packet received."));
      break;
    case SSH_VA_PACKET_ERROR:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("error happened during type detect."));
      break;
    }

  /* Free the packet now that we don't really need it anymore */
  ssh_interceptor_packet_free(pp);
}

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
