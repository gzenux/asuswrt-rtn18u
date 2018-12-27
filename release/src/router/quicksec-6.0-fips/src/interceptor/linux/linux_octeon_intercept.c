/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Hooks to the Cavium Octeon ethernet driver bypassing Linux netfilter.
*/

#include "linux_internal.h"
#include "sshgetput.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
#include <linux/mii.h>

#include "cavium-ethernet.h"
#include "linux_vrf.h"

#undef OCTEON_MODEL
#define USE_RUNTIME_MODEL_CHECKS 1

#include "octeon_se_fastpath_shared.h"

#include "cvmx.h"
#include "cvmx-wqe.h"

#define SSH_DEBUG_MODULE "SshInterceptorOcteon"

#define MAX_INPUT_PORTS 36

extern SshInterceptor ssh_interceptor_context;

static struct net_device *ssh_oct_device[MAX_INPUT_PORTS + 1];
static int ssh_num_oct_devices;


/*************** Conversion between ifindex and octeon port number **********/

uint8_t
ssh_interceptor_octeon_ifnum_to_port(SshInterceptor interceptor,
                                     SshInterceptorIfnum ifnum)
{
  struct net_device *dev;
  void *context = NULL;
  cvm_oct_private_t *priv;
  int i;
  uint8_t port = OCTEON_SE_FASTPATH_INVALID_PORT;

  if (ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    return OCTEON_SE_FASTPATH_INVALID_PORT;

  /* Fetch net_device. */
  dev = ssh_interceptor_ifnum_to_netdev_ctx(interceptor, ifnum, &context);
  if (dev == NULL)
    return OCTEON_SE_FASTPATH_INVALID_PORT;

  /* Interface context is not set, this might still be an octeon device. */
  if (context == NULL)
    {
      /* Check if this is an octeon device and set context pointer if it is. */
      for (i = 0; i < ssh_num_oct_devices; i++)
        {
          if (dev == ssh_oct_device[i])
            {
              ssh_interceptor_iface_set_context(interceptor, ifnum, dev);
              context = dev;
              break;
            }
        }
    }

  /* Interface context is set, this is an octeon device. */
  if (context != NULL)
    {
      /* Take octeon port number from net_device private data. */
      priv = (cvm_oct_private_t *) netdev_priv(dev);
      if (priv != NULL)
        port = priv->port;
    }

  /* Release the reference taken by ssh_interceptor_ifnum_to_netdev_ctx(). */
  ssh_interceptor_release_netdev(dev);

  return port;
}

SshInterceptorIfnum
ssh_interceptor_octeon_port_to_ifnum(SshInterceptor interceptor, uint8_t port)
{
  cvm_oct_private_t *priv;
  SshUInt32 i;

  for (i = 0; i < ssh_num_oct_devices; i++)
    {
      SSH_ASSERT(ssh_oct_device[i] != NULL);

      priv = (cvm_oct_private_t *) netdev_priv(ssh_oct_device[i]);
      if (priv == NULL)
        continue;

      if (priv->port == port)
        return (SshInterceptorIfnum) ssh_oct_device[i]->ifindex;
    }

  return SSH_INTERCEPTOR_INVALID_IFNUM;
}


/***************************** Module parameters ****************************/

int num_se_fastpaths = 1;
MODULE_PARM_DESC(num_se_fastpaths,
                 "Number of Octeon simple executive fastpaths");
module_param(num_se_fastpaths, int, 0444);

uint8_t
ssh_interceptor_octeon_get_num_fastpaths(SshInterceptor interceptor)
{
  return (uint8_t) num_se_fastpaths;
}

/***************************** Init / Uninit ********************************/

SSH_FASTTEXT cvm_oct_callback_result_t
ssh_octeon_interceptor_callback(struct net_device *dev,
                                void *work_queue_entry,
                                struct sk_buff *skb);

void
ssh_interceptor_octeon_init(SshInterceptor interceptor)
{
  unsigned char *iface_names[MAX_INPUT_PORTS];
  int num_ifaces, i;
  struct net_device *dev;
  struct net *net = &init_net;
  SshInterceptorVrf vrf;
  int vrf_id = 0;


  /* Allocate temporary space for device names. */
  memset(iface_names, 0, sizeof(iface_names));
  for (i = 0; i < MAX_INPUT_PORTS; i++)
    {
      iface_names[i] = ssh_calloc(1, IFNAMSIZ + 1);
      if (iface_names[i] == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Initialization failure"));
          ssh_warning("ssh_interceptor_octeon_init failed");
          goto out;
        }
    }

  /* Loop through the device list and store device names. */
  local_bh_disable();
  read_lock(&dev_base_lock);
  num_ifaces = 0;
  SSH_INTERCEPTOR_VRF_FOR_EACH_VRFID(net, vrf, vrf_id)
    {
      for (dev = SSH_FIRST_NET_DEVICE(net);
           dev != NULL;
           dev = SSH_NEXT_NET_DEVICE(dev))
        {
          ssh_snprintf(iface_names[num_ifaces], IFNAMSIZ, "%s", dev->name);
          num_ifaces++;
          if (num_ifaces == MAX_INPUT_PORTS)
            break;
        }
    }
  read_unlock(&dev_base_lock);
  local_bh_enable();

  /* Attempt to register intercept callback for all found devices. */
  memset(ssh_oct_device, 0, sizeof(ssh_oct_device));
  ssh_num_oct_devices = 0;
  for (i = 0; i < num_ifaces; i++)
    {
      dev = cvm_oct_register_callback(iface_names[i],
                                      ssh_octeon_interceptor_callback);
      if (dev != NULL)
        {
          SSH_ASSERT(ssh_num_oct_devices <= MAX_INPUT_PORTS);

          /* Take a reference to the device. */
          dev_hold(dev);
          ssh_oct_device[ssh_num_oct_devices] = dev;
          ssh_num_oct_devices++;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Registered intercept callback for dev '%s'", dev->name));
        }
    }

 out:
  /* Cleanup. */
  for (i = 0; i < MAX_INPUT_PORTS; i++)
    ssh_free(iface_names[i]);
}

void
ssh_interceptor_octeon_uninit(SshInterceptor interceptor)
{
  int i;

  for (i = 0; i < ssh_num_oct_devices; i++)
    {
      /* Unregister intercept callback. */
      SSH_ASSERT(ssh_oct_device[i] != NULL);
      cvm_oct_register_callback(ssh_oct_device[i]->name, NULL);

      /* Release reference to device. */
      dev_put(ssh_oct_device[i]);
      ssh_oct_device[i] = NULL;
    }
  ssh_num_oct_devices = 0;
}


/*************************** Packet interception ****************************/

void
ssh_interceptor_octeon_set_packet_cb(SshInterceptor interceptor,
                                     SshInterceptorOcteonPacketCB
                                     packet_callback,
                                     void *callback_context)
{
  /* The accelerated fastpath must set the packet handler callback before
     the SE fastpath is enabled. */
  SSH_ASSERT(packet_callback != NULL_FNPTR);
  interceptor->nf->octeon_packet_handler = packet_callback;
  interceptor->nf->octeon_packet_handler_context = callback_context;
}

/** The Octeon ethernet driver calls this callback when packets are received
    from the SE fastpath. Packets from local stack are never passed via this
    function but they are always passed via the normal interceptor packet
    callback. */
SSH_FASTTEXT cvm_oct_callback_result_t
ssh_octeon_interceptor_callback(struct net_device *dev,
                                void *work_queue_entry,
                                struct sk_buff *skb)
{
  SshInterceptorInternalPacket ipp;
  SshInterceptorProtocol protocol;
  cvmx_wqe_t *wqe = (cvmx_wqe_t *) work_queue_entry;
  SeFastpathControlCmd control = NULL;
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  SshCpuContext cpu_ctx;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  SSH_ASSERT(wqe != NULL);
  SSH_ASSERT(wqe->grp == OCTEON_SE_FASTPATH_PKT_GROUP
             || wqe->grp == OCTEON_SE_FASTPATH_SLOWPATH_GROUP);

  /* If this packet is submitted from SE fastpath to software fastpath
     then wqe contains the control command. */
  if (wqe->grp == OCTEON_SE_FASTPATH_SLOWPATH_GROUP)
    {
      control = (SeFastpathControlCmd) wqe->packet_data;
      SSH_ASSERT(control->cmd == OCTEON_SE_FASTPATH_CONTROL_CMD_SLOW);
    }

  /* Check if engine has connected. */
  if (ssh_interceptor_context->engine_open == FALSE)
    {







        return CVM_OCT_DROP;
    }

  /* Check packet type. Intercept only IPv4, IPv6 and ARP. */
  if (skb->protocol == __constant_htons(ETH_P_IP))
    protocol = SSH_PROTOCOL_IP4;
  else if (skb->protocol == __constant_htons(ETH_P_ARP))
    {
      if (SSH_SKB_GET_MACHDR(skb))
        {
          size_t media_header_len = skb->data - SSH_SKB_GET_MACHDR(skb);
          if (media_header_len)
            skb_push(skb, media_header_len);
        }
      protocol = SSH_PROTOCOL_ETHERNET;
    }
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  else if (skb->protocol == __constant_htons(ETH_P_IPV6))
    protocol = SSH_PROTOCOL_IP6;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */
  else
    return CVM_OCT_PASS;

  SSH_ASSERT(in_irq() == 0);
  SSH_ASSERT(in_softirq());

  /* Allocate SshInterceptorPacket. */
  ipp = ssh_interceptor_packet_alloc_header(ssh_interceptor_context,
                          SSH_PACKET_FROMADAPTER
                          | SSH_PACKET_IP4HDRCKSUMOK,
                          protocol,
                          dev->ifindex,
                          SSH_INTERCEPTOR_INVALID_IFNUM,
                          skb,
                          SSH_LINUX_PACKET_ALLOC_FLAG_PKT_FROM_SYSTEM
                          | SSH_LINUX_PACKET_ALLOC_FLAG_FREE_ORGINAL_ON_COPY);
  if (ipp == NULL)
    return CVM_OCT_DROP;

  SSH_DEBUG(SSH_D_PCKDMP,
            ("%s %s/0x%x dev %s[%d] len %d",
             (wqe->grp == OCTEON_SE_FASTPATH_SLOWPATH_GROUP ? "SLOW" : "IN"),
             (protocol == SSH_PROTOCOL_IP4 ? "IPv4" :
              (protocol == SSH_PROTOCOL_IP6 ? "IPv6" : "ethernet")),
             __constant_ntohs(ipp->skb->protocol),
             (ipp->skb->dev ? ipp->skb->dev->name : "<none>"),
             (ipp->skb->dev ? ipp->skb->dev->ifindex : -1),
             ipp->skb->len));

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Packet data"),
                    ipp->skb->data, ipp->skb->len);

#ifdef DEBUG_LIGHT
  ipp->skb->dev = NULL;
#endif /* DEBUG_LIGHT */

  /* Packet from network or unprocessed exception packet from SE fastpath. */
  if (control == NULL
      || control->prev_transform_index == OCTEON_SE_FASTPATH_INVALID_INDEX)
    {
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that cpu is executing an engine call. */
      cpu_ctx = &ssh_interceptor_context->cpu_ctx[ssh_kernel_get_cpu()];
      SSH_ASSERT(cpu_ctx->in_engine == 0);
      cpu_ctx->in_engine = 1;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

      SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(ssh_interceptor_context, ipp);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that the cpu is not executing an engine call. */
      SSH_ASSERT(cpu_ctx->in_engine == 1);
      cpu_ctx->in_engine = 0;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
    }

  /* Partially processed exception packet from SE fastpath. */
  else
    {
      SSH_ASSERT(ssh_interceptor_context->nf->octeon_packet_handler
                 != NULL_FNPTR);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that cpu is executing an engine call. */
      cpu_ctx = &ssh_interceptor_context->cpu_ctx[ssh_kernel_get_cpu()];
      SSH_ASSERT(cpu_ctx->in_engine == 0);
      cpu_ctx->in_engine = 1;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

      (*ssh_interceptor_context->nf->octeon_packet_handler)
        (&ipp->packet, control->tunnel_id, control->prev_transform_index,
         ssh_interceptor_context->nf->octeon_packet_handler_context);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that the cpu is not executing an engine call. */
      SSH_ASSERT(cpu_ctx->in_engine == 1);
      cpu_ctx->in_engine = 0;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
    }

  return CVM_OCT_TAKE_OWNERSHIP_SKB;
}

#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
