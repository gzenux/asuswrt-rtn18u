/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent IP protocol stack interface for Windows NT series
   operating systems. Currently this code supports only Windows 2000 and
   later. Legacy Windows NT 4.0 operating system is not supported any more.

   NOTE:

   There is no well-documented and supported API to retrieve the IP
   network information at Windows kernel-mode. All functions implemented
   below are using un-documented device I/O control calls and structures,
   so the operation of these functions should be checked with each
   Windows OS revision and updates.
*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "ipdevice.h"
#include "ipdevice_internal.h"
#include "kernel_timeouts.h"
#include "device_io.h"
#include <tdikrnl.h>
#include <tdiinfo.h>
#include <ipifcons.h>
#include <ntstatus.h>
#include <nldef.h>


#define TL_INSTANCE                     0 

#define SSH_MAX_IF_PHYSADDR_LEN         8      /* [8 bit] */ 
#define SSH_MAX_IP4_ADDR_LEN            4      /* [8 bit] */ 


typedef struct SshIPDeviceContextRec
{
  /* TCP (IPv4) / Ip6 device I/O context */
  SshDeviceIoContextStruct stack_device;
} SshIPDeviceContextStruct, *SshIPDeviceContext;

/* Asynchronous I/O requests are canceled if not completed in 6 seconds */
#define SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT    6

/* IPv4 I/O control codes */
#define FSCTL_IP_BASE                   FILE_DEVICE_NETWORK
#define _IP_CTL_CODE(function, method, access) \
            CTL_CODE(FSCTL_IP_BASE, function, method, access)

#define IOCTL_IP_SET_ADDRESS \
            _IP_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IP_ADD_ADDRESS \
            _IP_CTL_CODE(7, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IP_DELETE_ADDRESS \
            _IP_CTL_CODE(8, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IP_REFRESH_REQUEST \
            _IP_CTL_CODE(14, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* TCP/IPv4 I/O control codes */
#define FSCTL_TCP_BASE                  FILE_DEVICE_NETWORK
#define _TCP_CTL_CODE(function, method, access) \
            CTL_CODE(FSCTL_TCP_BASE, function, method, access)

#define IOCTL_TCP_QUERY_INFORMATION_EX  \
            _TCP_CTL_CODE(0, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_TCP_SET_INFORMATION_EX  \
            _TCP_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define SSH_IP4_MIB_IFTABLE_ENTRY_ID    0x0001
#define SSH_IP4_MIB_STATS_ID            0x0001
#define SSH_IP4_MIB_ROUTETABLE_ENTRY_ID 0x0101
#define SSH_IP4_MIB_ADDRTABLE_ENTRY_ID  0x0102

#if defined (WITH_IPV6)
/* Macro for checking if IPv6 interface is loopback interface */
#define SSH_IP6_IF_IS_LOOPBACK(ii)                              \
  (((SSH_IP6_IF)(ii))->if_id.index == 1)

/* TCP/IPv6 I/O control codes */
#define FSCTL_IPV6_BASE                 FILE_DEVICE_NETWORK
#define _IPV6_CTL_CODE(function, method, access) \
            CTL_CODE(FSCTL_IPV6_BASE, function, method, access)

#define IOCTL_IPV6_QUERY_INTERFACE \
            _IPV6_CTL_CODE(1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_PERSISTENT_QUERY_INTERFACE \
            _IPV6_CTL_CODE(48, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_QUERY_ADDRESS \
            _IPV6_CTL_CODE(2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_PERSISTENT_QUERY_ADDRESS \
            _IPV6_CTL_CODE(47, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_QUERY_ROUTE_TABLE \
            _IPV6_CTL_CODE(13, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_PERSISTENT_QUERY_ROUTE_TABLE \
            _IPV6_CTL_CODE(46, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_IPV6_UPDATE_ROUTE \
            _IPV6_CTL_CODE(14, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IPV6_PERSISTENT_UPDATE_ROUTE \
            _IPV6_CTL_CODE(40, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IPV6_UPDATE_ADDRESS \
            _IPV6_CTL_CODE(15, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_IPV6_PERSISTENT_UPDATE_ADDRESS \
            _IPV6_CTL_CODE(38, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#endif /* (WITH_IPV6) */

#pragma pack(push,1)

/* IPv4 specific structure descriptions */

/* Data structure for IPv4 address addition requests */
typedef struct SSH_IP4_ADD_ADDRESS_REQ_REC
{
  unsigned short addr_id;
  unsigned short unknown;
  unsigned char addr[SSH_MAX_IP4_ADDR_LEN];
  unsigned char mask[SSH_MAX_IP4_ADDR_LEN];
  UNICODE_STRING device_name;  /* \DEVICE\TCPIP_{...} */
  /* Actual device name must be appended here */
  unsigned short buffer[53];
} SSH_IP4_ADD_ADDRESS_REQ_STRUCT, *SSH_IP4_ADD_ADDRESS_REQ;

/* Data structure for IPv4 address set request */
typedef struct SSH_IP4_SET_ADDRESS_REQ_REC
{
  unsigned short addr_id;
  unsigned short unknown;
  unsigned char addr[SSH_MAX_IP4_ADDR_LEN];
  unsigned char mask[SSH_MAX_IP4_ADDR_LEN];
} SSH_IP4_SET_ADDRESS_REQ_STRUCT, *SSH_IP4_SET_ADDRESS_REQ;

/* Data structure containing IP device's IP address addition response. */
typedef struct SSH_IP4_ADD_ADDRESS_RESP_REC
{
  unsigned short addr_id;
  unsigned short unknown[3];
} SSH_IP4_ADD_ADDRESS_RESP_STRUCT, *SSH_IP4_ADD_ADDRESS_RESP;

/* Data structure for IPv4 address deletion requests */
typedef struct SSH_IP4_DEL_ADDRESS_REQ_REC
{
  unsigned short addr_id;
} SSH_IP4_DEL_ADDRESS_REQ_STRUCT, *SSH_IP4_DEL_ADDRESS_REQ;

/* Descriptor for IPv4 statistics */
typedef struct SSH_IP4_STATS_REC
{
  unsigned long forwarding;
  unsigned long defaultttl;
  unsigned long inreceives;
  unsigned long inhdrerrors;
  unsigned long inaddrerrors;
  unsigned long forwdatagrams;
  unsigned long inunknownprotos;
  unsigned long indiscards;
  unsigned long indelivers;
  unsigned long outrequests;
  unsigned long routingdiscards;
  unsigned long outdiscards;
  unsigned long outnoroutes;
  unsigned long reasmtimeout;
  unsigned long reasmreqds;
  unsigned long reasmoks;
  unsigned long reasmfails;
  unsigned long fragoks;
  unsigned long fragfails;
  unsigned long fragcreates;
  unsigned long numif;
  unsigned long numaddr;
  unsigned long numroutes;
} SSH_IP4_STATS_STRUCT, *SSH_IP4_STATS;

/* Descriptor for IPv4 interface entry */
typedef struct SSH_IP4_IF_REC
{
  unsigned long index;
  unsigned long type;
  unsigned long mtu;
  unsigned long speed;
  unsigned long phys_addr_len;
  unsigned char phys_addr[SSH_MAX_IF_PHYSADDR_LEN];
  unsigned long admin_status;
  INTERNAL_IF_OPER_STATUS oper_status;
  unsigned long last_changed;
  unsigned long in_octects;
  unsigned long in_ucast_pkts;
  unsigned long in_nucast_pkts;
  unsigned long in_discards;
  unsigned long in_errors;
  unsigned long in_unknown_protos;
  unsigned long out_octets;
  unsigned long out_ucast_pkts;
  unsigned long out_nucast_pkts;
  unsigned long out_discards;
  unsigned long out_errors;
  unsigned long out_qlen;
  unsigned long descr_len;
  unsigned char descr[SSH_MAX_IF_DESCR_LEN];
} SSH_IP4_IF_STRUCT, *SSH_IP4_IF;

/* Descriptor for IPv4 address table entry */
typedef struct SSH_IP4_ADDR_REC
{
  unsigned char addr[SSH_MAX_IP4_ADDR_LEN];
  unsigned long if_index;
  unsigned char subnet_mask[SSH_MAX_IP4_ADDR_LEN];
  unsigned char broadcast_addr[SSH_MAX_IP4_ADDR_LEN];
  unsigned long reasm_size;
  unsigned short addr_id;
  unsigned short type;
} SSH_IP4_ADDR_STRUCT, *SSH_IP4_ADDR;

/* Descriptor for IPv4 route table entry */
typedef struct SSH_IP4_FORWARD_REC
{
  unsigned char dest[SSH_MAX_IP4_ADDR_LEN];
  unsigned long if_index;
  int metric1;
  int metric2;
  int metric3;
  int metric4;
  unsigned char next_hop[SSH_MAX_IP4_ADDR_LEN];
  unsigned long type;
  unsigned long protocol;
  unsigned long policy;
  unsigned char mask[SSH_MAX_IP4_ADDR_LEN];
  int metric5;
  unsigned long unknown1;
} SSH_IP4_FORWARD_STRUCT, *SSH_IP4_FORWARD;

#if defined (WITH_IPV6)
/* IPv6 specific structure descriptions */

/* Decriptor for IPv6 interface table entry */
typedef struct SSH_IP6_IF_IDENTIDIER_REC
{
  unsigned long index;
  GUID guid;
} SSH_IP6_IF_IDENTIFIER_STRUCT, *SSH_IP6_IF_IDENTIFIER;


typedef struct SSH_IP6_IF
{
  SSH_IP6_IF_IDENTIFIER_STRUCT next_id;
  SSH_IP6_IF_IDENTIFIER_STRUCT if_id;
  unsigned long body_size;
  unsigned long media_addr_len;
  unsigned long local_media_addr_offset;
  unsigned long remote_media_addr_offset;
  unsigned long type;
  unsigned long router_discovers;
  unsigned long neighbor_discovers;
  unsigned long periodic_mld;
  unsigned long advertises;
  unsigned long forwards;
  unsigned long media_status;
  unsigned long unknown[19]; /* two extra fields here... */
  unsigned long true_link_mtu;
  unsigned long link_mtu;
  unsigned long hop_limit;
  unsigned long reachable_time_base;
  unsigned long reachable_time;
  unsigned long retransmit_interval;
  unsigned long dad_transmits;
  unsigned long routing_preference;
  unsigned long firewall_enabled;
  unsigned long def_site_prefix_len;
  unsigned char extra_info[22];
} SSH_IP6_IF_STRUCT, *SSH_IP6_IF;



/* Decriptor for IPv6 address table entry */
typedef struct SSH_IP6_ADDR_ID_REC
{
  SSH_IP6_IF_IDENTIFIER_STRUCT if_id;
  unsigned char addr[SSH_MAX_IP6_ADDR_LEN];
} SSH_IP6_ADDR_ID_STRUCT, *SSH_IP6_ADDR_ID;


typedef struct SSH_IP6_ADDR_REC
{
  SSH_IP6_ADDR_ID_STRUCT next_addr;
  SSH_IP6_ADDR_ID_STRUCT addr;
  unsigned long type;
  unsigned long scope;
  unsigned long scope_id;
  NL_DAD_STATE dad_state;
  unsigned long prefix_conf;
  unsigned long interface_id_conf;
  unsigned long valid_life_time;
  unsigned long preferred_life_time;
} SSH_IP6_ADDR_STRUCT, *SSH_IP6_ADDR;


typedef struct SSH_IP6_ADDR_UPDATE_REC
{
  SSH_IP6_IF_IDENTIFIER_STRUCT if_id;
  unsigned char addr[SSH_MAX_IP6_ADDR_LEN];
  unsigned long type;
  unsigned long prefix_conf;
  unsigned long interface_id_conf;
  unsigned long preferred_life_time;
  unsigned long valid_life_time;
} SSH_IP6_ADDR_UPDATE_STRUCT, *SSH_IP6_ADDR_UPDATE;

/* Descriptor for IPv6 route table entry */
typedef struct SSH_IP6_ROUTE_REC
{
  struct SSH_IP6_ROUTE_QUERY_REC
    {
    unsigned char dest[SSH_MAX_IP6_ADDR_LEN];
    unsigned long prefix_len;
    SSH_IP6_IF_IDENTIFIER_STRUCT if_id;
    unsigned char next_hop[SSH_MAX_IP6_ADDR_LEN];
    }
  route;

  unsigned long site_prefix_len;

  long valid_life_time;
  long preferred_life_time;
  unsigned long preference;

  long type;

  long publish;
  long age;

} SSH_IP6_ROUTE_STRUCT, *SSH_IP6_ROUTE;
#endif /* (WITH_IPV6) */

#pragma pack(pop)

typedef struct SshIoCompletionRec
{
  /* IP device object */
  SshIPDevice ip_dev;

  /* Upper level callback function to be called when IRP completes */
  SshIPDeviceCompletionCB callback;

  /* Context parameter to be sent to 'callback' */
  void *context;

  /* Do we close the io_ctx on call completion? */
  Boolean close_on_completion; 
  SshDeviceIoContext io_ctx;

  /* The IRP we've requested to be processed. */
  PIRP irp;
} SshIoCompletionStruct, *SshIoCompletion;


/*--------------------------------------------------------------------------
  Local functions
  --------------------------------------------------------------------------*/

IO_COMPLETION_ROUTINE ssh_ipdev_ioctl_completion_routine;

static Boolean
ssh_ipdev_ip4_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list);

static Boolean
ssh_ipdev_ip4_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list);

static Boolean
ssh_ipdev_ip4_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list);

static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex ,
                                 SshAddressCtx *ctx_return);

static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params);

static void
ssh_ipdev_ip4_clear_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context);

static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip4_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip4_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context);

static void
ssh_ipdev_ip4_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context);

static void
ssh_ipdev_ip4_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context);

#if defined (WITH_IPV6)
static Boolean
ssh_ipdev_ip6_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list);

static Boolean
ssh_ipdev_ip6_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list);

static Boolean
ssh_ipdev_ip6_query_routes(SshIPDevice device,
                           SshIpdevRouteList);

static void
ssh_ipdev_ip6_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip6_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context);

static void
ssh_ipdev_ip6_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context);

static void
ssh_ipdev_ip6_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context);

#endif /* (WITH_IPV6) */

/*--------------------------------------------------------------------------
  Exported Windows 2K/XP/2K3 platform dependent functions.
  --------------------------------------------------------------------------*/

Boolean
ssh_ipdev_platform_init(SshIPDevice device)
{
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate context!"));
      return FALSE;
    }
  device->context = ctx;

  if (device->dev_id == SSH_DD_ID_IP4)
    {
      device->query_interface_list = ssh_ipdev_ip4_query_interfaces;
      device->query_address_list = ssh_ipdev_ip4_query_addresses;
      device->query_route_list = ssh_ipdev_ip4_query_routes;
      device->find_first_address = ssh_ipdev_ip4_find_first_address;
      device->clear_address = ssh_ipdev_ip4_clear_address;
      device->set_address = ssh_ipdev_ip4_set_address;
      device->add_address = ssh_ipdev_ip4_add_address;
      device->delete_address = ssh_ipdev_ip4_delete_address;
      device->add_route = ssh_ipdev_ip4_add_route;
      device->remove_route = ssh_ipdev_ip4_remove_route;
      device->configure = ssh_ipdev_configure_i;
    }
#if defined (WITH_IPV6)
  else /* IPv6 */
    {
      device->query_interface_list = ssh_ipdev_ip6_query_interfaces;
      device->query_address_list = ssh_ipdev_ip6_query_addresses;
      device->query_route_list = ssh_ipdev_ip6_query_routes;
      device->add_address = ssh_ipdev_ip6_add_address;
      device->delete_address = ssh_ipdev_ip6_delete_address;
      device->add_route = ssh_ipdev_ip6_add_route;
      device->remove_route = ssh_ipdev_ip6_remove_route;
      device->configure = ssh_ipdev_configure_i;
    }
#else
  else
    {
      return FALSE;
    }
#endif /* (WITH_IPV6) */

  return TRUE;
}


void
ssh_ipdev_platform_uninit(SshIPDevice device)
{
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);

  ctx = device->context;

  ssh_free(ctx);
}


Boolean
ssh_ipdev_platform_connect(SshIPDevice device)
{
  SshDeviceIoOpenParamsStruct open_params;
  WCHAR *device_name;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  ctx = device->context;

  RtlZeroMemory(&open_params, sizeof(open_params));
  open_params.write_access = FALSE;
  open_params.exclusive_access = FALSE;
  open_params.default_timeout = SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT;
  open_params.disable_count_ptr = &device->suspend_count;
  open_params.requests_pending_ptr = &device->requests_pending;

  if (device->dev_id == SSH_DD_ID_IP4)
    {
      device_name = L"\\Device\\Tcp";
    }
#if defined (WITH_IPV6)
  else /* IPv6 */
    {
      device_name = L"\\Device\\Ip6";
    }
#else
  else
    {
      return FALSE;
    }
#endif /* (WITH_IPV6) */

  if (!ssh_device_open(&ctx->stack_device, device_name, &open_params))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to open %s device!",
                 (device->dev_id == SSH_DD_ID_IP4) ? "IPv4" : "IPv6"));
      return FALSE;
    }

  return TRUE;
}


void 
ssh_ipdev_platform_disconnect(SshIPDevice device)
{
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  ctx = device->context;

  ssh_device_close(&ctx->stack_device);
}


static void
ssh_ipdev_ip4_decode_interface(SshIpdevInterfaceInfo if_info,
                               SSH_IP4_IF ip4_ii)
{
  SSH_ASSERT(if_info != NULL);
  SSH_ASSERT(ip4_ii != NULL);

  RtlZeroMemory(if_info, sizeof(*if_info));

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                    ("- Description (len=%u):", ip4_ii->descr_len), 
                    ip4_ii->descr, ip4_ii->descr_len);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Index: %u", ip4_ii->index));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip4_ii->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- MTU: %u", ip4_ii->mtu));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Speed: %u", ip4_ii->speed));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("- Physical address:"),
                    ip4_ii->phys_addr, ip4_ii->phys_addr_len);
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- AdminStatus: %u", ip4_ii->admin_status));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- OperStatus: %u", ip4_ii->oper_status));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- LastChanged: %u", ip4_ii->last_changed));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- InOctets: %u", ip4_ii->in_octects));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- InUcastPkts: %u", ip4_ii->in_ucast_pkts));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- InNUcastPkts: %u", ip4_ii->in_nucast_pkts));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- InDiscards: %u", ip4_ii->in_discards));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- InErrors: %u", ip4_ii->in_errors));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- InUnknownProtos: %u", ip4_ii->in_unknown_protos));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- OutOctets: %u", ip4_ii->out_octets));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- OutUcastPkts: %u", ip4_ii->out_ucast_pkts));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- OutNUcastPkts: %u", ip4_ii->out_nucast_pkts));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- OutDiscards: %u", ip4_ii->out_discards));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- OutErrors: %u", ip4_ii->out_errors));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- OutQueueLen: %u", ip4_ii->out_qlen));

  if (ip4_ii->type == MIB_IF_TYPE_LOOPBACK)
    if_info->is_loopback = 1;

  /* Indexes */
  if_info->system_idx = ip4_ii->index;

  /* Save interface description (and length), because this will be later
     needed in adapter object lookup (in case there are more than one
     virtual adapters having the same media address). */
  SSH_ASSERT(ip4_ii->descr_len <= SSH_MAX_IF_DESCR_LEN);
  RtlCopyMemory(if_info->id.u.d.description, 
                ip4_ii->descr, 
                ip4_ii->descr_len);
  if_info->id.u.d.description_len = ip4_ii->descr_len;
  if_info->id.id_type = SSH_IF_ID_DESCRIPTION;

  /* Media address */
  if_info->media_addr_len = SSH_ETHERH_ADDRLEN;
  RtlCopyMemory(if_info->media_address,
                ip4_ii->phys_addr,
                if_info->media_addr_len);
  if_info->has_media_address = 1;

  /* MTU */
  SSH_ASSERT(ip4_ii->mtu != 0);
  if_info->mtu = ip4_ii->mtu;
  if_info->has_mtu = 1;
}


static void
ssh_ipdev_ip4_decode_route(SshIpdevRouteInfo route,
                           SSH_IP4_FORWARD ip4_ri)
{
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(ip4_ri != NULL);

  RtlZeroMemory(route, sizeof(*route));

  /* Set destination, mask and next hop address */
  SSH_IP4_DECODE(&route->dest, ip4_ri->dest);
  SSH_IP4_DECODE(&route->gw, ip4_ri->next_hop);
  SSH_IP4_DECODE(&route->nm, ip4_ri->mask);
  route->nm_len = ssh_ip_net_mask_calc_prefix_len(&route->nm);

  /* Indexes */
  route->system_idx = ip4_ri->if_index;

  /* Route type */
  route->type = ((ip4_ri->type == 3) ?
                 SSH_IP_ROUTE_DIRECT : SSH_IP_ROUTE_INDIRECT);

  /* 1st metric */
  route->metric = ip4_ri->metric1;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Dest: %@", ssh_ipaddr_render, &route->dest));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Mask: %@", ssh_ipaddr_render, &route->nm));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHop: %@", ssh_ipaddr_render, &route->gw));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IfIndex: %u (0x%X)", 
             ip4_ri->if_index, ip4_ri->if_index));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip4_ri->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Policy: %u", ip4_ri->policy));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Proto: %u", ip4_ri->protocol));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric1: %u", ip4_ri->metric1));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric2: %u", ip4_ri->metric2));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric3: %u", ip4_ri->metric3));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric4: %u", ip4_ri->metric4));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric5: %u", ip4_ri->metric5));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("(- MTU: %u)", route->mtu));
}


static void
ssh_ipdev_ip4_decode_address(SshIpdevAddressInfo addr,
                             SSH_IP4_ADDR ip4_ai)
{
  static unsigned char ba[4] = {0x00, 0x00, 0x00, 0x00};
  static unsigned char ba_mask[4] = {0xFF,0xFF,0xFF,0xFF};
  unsigned int i;

  SSH_ASSERT(addr != NULL);
  SSH_ASSERT(ip4_ai != NULL);

  RtlZeroMemory(addr, sizeof(*addr));

  addr->if_addr.protocol = SSH_PROTOCOL_IP4;
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.ip, ip4_ai->addr);
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.mask, ip4_ai->subnet_mask);

  /* Generate broadcast address */
  for (i = 0; i < 4; i++)
    {
      ba[i] = (ip4_ai->addr[i] & ip4_ai->subnet_mask[i]) |
               (ba_mask[i] & ~(ip4_ai->subnet_mask[i]));
    }
  SSH_IP4_DECODE(&addr->if_addr.addr.ip.broadcast, ba);

  addr->system_idx = ip4_ai->if_index;
  addr->address_id = ip4_ai->addr_id;
  addr->type = ip4_ai->type;
  addr->dad_state = IpDadStatePreferred;
  addr->valid_lifetime = (SshUInt32)-1;     /* Not used */
  addr->preferred_lifetime = (SshUInt32)-1; /* Not used */
  addr->reasm_size = ip4_ai->reasm_size;
  addr->timestamp = (SshUInt32)-1;          /* Not used */








  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.ip));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Mask: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.mask));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Broadcast address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.broadcast));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ID: %u", ip4_ai->addr_id));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IfIndex: %u (0x%X)", 
             ip4_ai->if_index, ip4_ai->if_index));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- ReasmSize: %u", addr->reasm_size));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Type: %u", ip4_ai->type));
}

#if defined (WITH_IPV6)
static void
ssh_ipdev_ip6_decode_interface(SshIpdevInterfaceInfo if_info,
                               SSH_IP6_IF ip6_ii)

{
  SSH_ASSERT(if_info != NULL);
  SSH_ASSERT(ip6_ii != NULL);

  RtlZeroMemory(if_info, sizeof(*if_info));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Index: %u", ip6_ii->if_id.index));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- GUID: %@", ssh_guid_render, &ip6_ii->if_id.guid));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Size: %u", ip6_ii->body_size));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- LocalMediaAddrOffset: %u", 
             ip6_ii->local_media_addr_offset));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- RemoteMediaAddrOffset: %u", 
             ip6_ii->remote_media_addr_offset));
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, 
                    ("- Physical address (len=%u):", 
                     ip6_ii->media_addr_len),
                    (char *)ip6_ii + ip6_ii->local_media_addr_offset,
                    ip6_ii->media_addr_len);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip6_ii->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- MediaStatus: %u", ip6_ii->media_status));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- TrueLinkMTU: %u", ip6_ii->true_link_mtu));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- LinkMTU: %u", ip6_ii->link_mtu));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- DADTransmits: %u", ip6_ii->dad_transmits));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- FirewallEnabled: %u", ip6_ii->firewall_enabled));

  /* Skip possible loopback interface */
  if (SSH_IP6_IF_IS_LOOPBACK(ip6_ii))
    if_info->is_loopback = 1;

  /* Indexes */
  if_info->system_idx = ip6_ii->if_id.index;

  /* Save interface GUID, because this will be later needed in adapter
     object lookup (in case there are more than one virtual adapters
     having the same media address). */
  if_info->id.u.guid = ip6_ii->if_id.guid;
  if_info->id.id_type = SSH_IF_ID_GUID;

  /* Physical address */
  if (ip6_ii->media_addr_len == SSH_ETHERH_ADDRLEN)
    {
      RtlCopyMemory(if_info->media_address,
                    (char *)ip6_ii + ip6_ii->local_media_addr_offset,
                    SSH_ETHERH_ADDRLEN);

      if_info->media_addr_len = SSH_ETHERH_ADDRLEN;
      if_info->has_media_address = 1;
    }
  else
    {
      if_info->media_addr_len = 0;
      if_info->has_media_address = 0;
    }

  /* MTU */
  if_info->mtu = ip6_ii->link_mtu;
  if_info->has_mtu = 1;
}


static void
ssh_ipdev_ip6_decode_route(SshIpdevRouteInfo route,
                           SSH_IP6_ROUTE ip6_ri)
{
  unsigned char mask[16];

  SSH_ASSERT(route != NULL);
  SSH_ASSERT(ip6_ri != NULL);

  RtlZeroMemory(route, sizeof(*route));

  /* Set destination, mask, and next hop address */
  SSH_IP6_DECODE(&route->dest, ip6_ri->route.dest);
  SSH_IP6_DECODE(&route->gw, ip6_ri->route.next_hop);
  ssh_ip_net_mask_from_prefix_len(ip6_ri->route.prefix_len, mask, 16);
  SSH_IP6_DECODE(&route->nm, mask);
  route->nm_len = ip6_ri->route.prefix_len;

  /* Indexes */
  route->system_idx = ip6_ri->route.if_id.index;

  /* Determine route type */
  route->type = (SSH_IP_IS_NULLADDR(&route->gw)?
                 SSH_IP_ROUTE_DIRECT : SSH_IP_ROUTE_INDIRECT);

  route->metric = ip6_ri->preference;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Dest: %@", ssh_ipaddr_render, &route->dest));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Mask: %@", ssh_ipaddr_render, &route->nm));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHop: %@", ssh_ipaddr_render, &route->gw));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- IfIndex: %u (0x%X)", 
             route->system_idx, route->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", ip6_ri->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- SitePrefixLength: %u", ip6_ri->site_prefix_len));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- ValidLiftime: %u", ip6_ri->valid_life_time));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PreferredLifetime: %u", ip6_ri->preferred_life_time));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Preference: %u", ip6_ri->preference));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Publish: %u", ip6_ri->publish));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Age: %u", ip6_ri->age));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("(- MTU: %u)", route->mtu));
}


static void
ssh_ipdev_ip6_decode_address(SshIpdevAddressInfo addr,
                             SSH_IP6_ADDR ip6_ai)
{
  unsigned char mask[16];

  SSH_ASSERT(addr != NULL);
  SSH_ASSERT(ip6_ai != NULL);

  RtlZeroMemory(addr, sizeof(*addr));

  addr->if_addr.protocol = SSH_PROTOCOL_IP6;
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.ip, ip6_ai->addr.addr);

  /* Take the scope ID. */
  addr->if_addr.addr.ip.ip.scope_id.scope_id_union.ui32 = 
    ip6_ai->scope_id;

  if (SSH_IP6_BYTE1(&addr->if_addr.addr.ip.ip) == 0x00)
    /* IPv6 addresses with embedded IPv4 addresses */
    ssh_ip_net_mask_from_prefix_len(96, mask, 16);
  else if (SSH_IP6_IS_SITE_LOCAL(&addr->if_addr.addr.ip.ip))
    ssh_ip_net_mask_from_prefix_len(64, mask, 16);
  else if (SSH_IP6_IS_LINK_LOCAL(&addr->if_addr.addr.ip.ip))
    ssh_ip_net_mask_from_prefix_len(10, mask, 16);
  else
    ssh_ip_net_mask_from_prefix_len(64, mask, 16);
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.mask, mask);

  /* Set broadcast address to IPv6 undefined address */
  SSH_IP6_DECODE(&addr->if_addr.addr.ip.broadcast, 
                 SSH_IP6_UNDEFINED_ADDR);

  addr->system_idx = ip6_ai->addr.if_id.index;
  addr->type = ip6_ai->type;
  addr->dad_state = ip6_ai->dad_state;
  addr->valid_lifetime = ip6_ai->valid_life_time;
  addr->preferred_lifetime = ip6_ai->preferred_life_time;
  addr->reasm_size = (SshUInt32)-1;  /* Not used */
  addr->timestamp = (SshUInt32)-1;   /* Not used */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.ip));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ScopeID: %u", ip6_ai->scope_id));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Mask: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.mask));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Broadcast address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.broadcast));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- InterfaceID: %u", addr->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Type: %u", addr->type));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Scope: %u", ip6_ai->scope));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- DADState: %u", addr->dad_state));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ValidLifetime: %u", addr->valid_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PreferredLifetime: %u", addr->preferred_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- PrefixConf: %u", ip6_ai->prefix_conf));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- InterfaceIdConf: %u", ip6_ai->interface_id_conf));
}
#endif /* (WITH_IPV6) */


/*--------------------------------------------------------------------------
  Local Windows 2K/XP/2K3 platform dependent functions.
  --------------------------------------------------------------------------*/

static Boolean
ssh_tcp_query_information_ex(SshIPDevice device,
                             ULONG entity,
                             ULONG instance,
                             ULONG info_class,
                             ULONG info_type,
                             ULONG id,
                             VOID *data,
                             ULONG *data_len)
{
  TCP_REQUEST_QUERY_INFORMATION_EX req;
  SshDeviceIoRequestStruct ioctl_req;
  SshIPDeviceContext ctx = device->context;

  SSH_ASSERT(ctx != NULL);

  /* Build extended query information */
  RtlZeroMemory(&req, sizeof(req));
  req.ID.toi_entity.tei_entity = entity;
  req.ID.toi_entity.tei_instance = instance;
  req.ID.toi_class = info_class;
  req.ID.toi_type = info_type;
  req.ID.toi_id = id;

  RtlZeroMemory(&ioctl_req, sizeof(ioctl_req));
  ioctl_req.ioctl_code = IOCTL_TCP_QUERY_INFORMATION_EX;
  ioctl_req.internal_device_control = FALSE;
  ioctl_req.input_buffer = &req,
  ioctl_req.input_buff_len = sizeof(req);
  ioctl_req.output_buffer = data;
  ioctl_req.output_buff_len = *data_len; 
  ioctl_req.output_size_return = data_len;

  if (NT_SUCCESS(ssh_device_ioctl_request(&ctx->stack_device, &ioctl_req)))
    return TRUE;
  else
    return FALSE;
}


static Boolean
ssh_tcp_query_entity_ids(SshIPDevice device,
                         TDIEntityID **list_return,
                         SshUInt32 *count_return)
{
  TDIEntityID *list;
  Boolean status = FALSE;
  SshUInt32 mem_size = (MAX_TDI_ENTITIES * sizeof(TDIEntityID));

  /* Allocate memory for entity ID's */
  list = ssh_calloc(1, mem_size);
  if (list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for TDI entities"));

      return FALSE;
    }

  status = ssh_tcp_query_information_ex(device,
                                        GENERIC_ENTITY,
                                        TL_INSTANCE,
                                        INFO_CLASS_GENERIC,
                                        INFO_TYPE_PROVIDER,
                                        ENTITY_LIST_ID,
                                        list,
                                        &mem_size);

  if (status != FALSE)
    {
      *list_return = list;
      *count_return = mem_size / sizeof(TDIEntityID);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query TDI entity IDs!"));

      *count_return = 0;
      *list_return = NULL;

      ssh_free(list);
    }

  return status;
}


static Boolean
ssh_tcp_query_entity_type(SshIPDevice device,
                          TDIEntityID *entity_id,
                          ULONG *type_return)
{
  ULONG len;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(entity_id != NULL);
  SSH_ASSERT(type_return != NULL);

  len = sizeof(*type_return);
  if (!ssh_tcp_query_information_ex(device,
                                    entity_id->tei_entity,
                                    entity_id->tei_instance,
                                    INFO_CLASS_GENERIC,
                                    INFO_TYPE_PROVIDER,
                                    ENTITY_TYPE_ID,
                                    type_return,
                                    &len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query entity type!"));
      return(FALSE);
    }

  return TRUE;
}


static Boolean
ssh_tcp_query_statistics(SshIPDevice device,
                         TDIEntityID *entity_id,
                         SSH_IP4_STATS stats_return)
{
  ULONG len;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(stats_return != NULL);

  len = sizeof(*stats_return);
  if (ssh_tcp_query_information_ex(device,
                                   entity_id->tei_entity,
                                   entity_id->tei_instance,
                                   INFO_CLASS_PROTOCOL,
                                   INFO_TYPE_PROVIDER,
                                   SSH_IP4_MIB_STATS_ID,
                                   stats_return, &len))
    {
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv4 statisctics"));
      return FALSE;
    }
}


static Boolean
ssh_ipdev_ip4_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list)
{
  SshIpdevInterfaceInfo decoded_copy = NULL;
  TDIEntityID *entity_id_list;
  SshUInt32 entity_count;
  SshUInt32 num_ifs = 0;
  SshUInt32 i;
  Boolean status = FALSE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(if_list != NULL);

  if (ssh_tcp_query_entity_ids(device, &entity_id_list, &entity_count))
    {
      status = TRUE;

      for (i = 0; (i < entity_count) && (status == TRUE); i++)
        {
          SSH_IP4_IF_STRUCT ip4_if;
          TDIEntityID *entity_id = &entity_id_list[i];
          ULONG entity_type;
          ULONG len;

          if (entity_id->tei_entity != IF_ENTITY)
            continue;

          if (!ssh_tcp_query_entity_type(device, entity_id, &entity_type))
            continue;

          if (entity_type != IF_MIB)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Unsupported TDI entity type "
                         "(%u instead of the expected %u)",
                         entity_type, IF_MIB));
              continue;
            }

          /* Query Interface Entry */
          len = sizeof(ip4_if);
          RtlZeroMemory(&ip4_if, len);
          if (!ssh_tcp_query_information_ex(device,
                                            entity_id->tei_entity,
                                            entity_id->tei_instance,
                                            INFO_CLASS_PROTOCOL,
                                            INFO_TYPE_PROVIDER,
                                            SSH_IP4_MIB_IFTABLE_ENTRY_ID,
                                            &ip4_if,
                                            &len))
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Failed to query IPv4 interface table entry"));
              continue;
            }
          else
            {
              size_t if_struct_size = sizeof(*decoded_copy);
              size_t old_size = num_ifs * if_struct_size;
              size_t new_size = old_size + if_struct_size;
              SshIpdevInterfaceInfo old_ifs = decoded_copy;

              decoded_copy = ssh_realloc(old_ifs, old_size, new_size);
              if (decoded_copy == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                           ("Failed to allocate memory for IPv4 interface!"));
                  ssh_free(old_ifs);
                  status = FALSE;
                  break;
                }

              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("----- IPv4 interface %u: -----", num_ifs));
              ssh_ipdev_ip4_decode_interface(&decoded_copy[num_ifs], &ip4_if);
              num_ifs++;
            }
        }

      ssh_free(entity_id_list);
    }

  if (status != FALSE)
    {
      if_list->table = decoded_copy;
      if_list->num_items = num_ifs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to query IPv4 interface information."));
      ssh_free(decoded_copy);
    }

  return status;
}


static Boolean
ssh_ipdev_ip4_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list)
{
  SshIpdevAddressInfo decoded_copy = NULL;
  TDIEntityID *entity_id_list;
  SshUInt32 entity_count;
  SshUInt32 num_addrs = 0;
  Boolean status = FALSE;
  SshUInt32 i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_list != NULL);

  if (ssh_tcp_query_entity_ids(device, &entity_id_list, &entity_count))
    {
      status = TRUE;

      for (i = 0; i < entity_count; i++)
        {
          TDIEntityID *entity_id = &entity_id_list[i];
          SSH_IP4_STATS_STRUCT statistics;
          ULONG entity_type;

          if (entity_id->tei_entity != CL_NL_ENTITY)
            continue;

          if (!ssh_tcp_query_entity_type(device, entity_id, &entity_type))
            continue;

          if (entity_type != CL_NL_IP)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Unsupported TDI entity type "
                         "(%u instead of the expected %u)",
                         entity_type, CL_NL_IP));
              continue;
            }

          RtlZeroMemory(&statistics, sizeof(statistics));
          status = ssh_tcp_query_statistics(device, entity_id, &statistics);
          if (status != FALSE)
            {
              SSH_IP4_ADDR addr_table;
              SshUInt32 j;
              ULONG len;

              if (statistics.numaddr == 0)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("No IPv4 addresses available"));
                  continue;
                }

              /* Query IP Address Table */
              addr_table = ssh_calloc(statistics.numaddr, 
                                      sizeof(*addr_table));
              if (addr_table == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, 
                            ("Failed to allocate memory for IPv4 "
                             "address table query"));
                  status = FALSE;
                  continue;
                }

              len = statistics.numaddr * sizeof(*addr_table);
              status = 
                ssh_tcp_query_information_ex(device,
                                             entity_id->tei_entity,
                                             entity_id->tei_instance,
                                             INFO_CLASS_PROTOCOL,
                                             INFO_TYPE_PROVIDER,
                                             SSH_IP4_MIB_ADDRTABLE_ENTRY_ID,
                                             addr_table, &len);

              for (j = 0; 
                   (status == TRUE) && (j < len / sizeof(*addr_table)); 
                   j++)
                {
                  SSH_IP4_ADDR addr = &addr_table[j];
                  size_t addr_size = sizeof(*decoded_copy);
                  size_t old_size = num_addrs * addr_size;
                  size_t new_size = old_size + addr_size;
                  SshIpdevAddressInfo old_addrs = decoded_copy;

                  decoded_copy = ssh_realloc(old_addrs, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Failed to allocate memory for IPv4 "
                                 "addresses!"));
                      ssh_free(old_addrs);
                      status = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv4 address %u: -----", num_addrs));
                  ssh_ipdev_ip4_decode_address(&decoded_copy[num_addrs], 
                                               addr);
                  num_addrs++;
                }

              ssh_free(addr_table);
            }
        }

      ssh_free(entity_id_list);
    }

  if (status != FALSE)
    {
      addr_list->table = decoded_copy;
      addr_list->num_items = num_addrs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to query IPv4 address table!"));
      ssh_free(decoded_copy);
    }

  return status;  
}


static Boolean
ssh_ipdev_ip4_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list)
{
  SshIpdevRouteInfo decoded_copy = NULL;
  TDIEntityID *entity_id_list;
  SshUInt32 entity_count;
  SshUInt32 num_routes = 0;
  Boolean status = FALSE;
  SshUInt32 i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(route_list != NULL);

  if (ssh_tcp_query_entity_ids(device, &entity_id_list, &entity_count))
    {
      status = TRUE;

      for (i = 0; i < entity_count; i++)
        {
          TDIEntityID *entity_id = &entity_id_list[i];
          SSH_IP4_STATS_STRUCT statistics;
          ULONG entity_type;

          if (entity_id->tei_entity != CL_NL_ENTITY)
            continue;

          if (!ssh_tcp_query_entity_type(device, entity_id, &entity_type))
            continue;

          if (entity_type != CL_NL_IP)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Unsupported TDI entity type "
                         "(%u instead of the expected %u)",
                         entity_type, CL_NL_IP));
              continue;
            }

          RtlZeroMemory(&statistics, sizeof(statistics));
          status = ssh_tcp_query_statistics(device, entity_id, &statistics);
          if (status != FALSE)
            {
              SSH_IP4_FORWARD route_table;
              SshUInt32 j;
              ULONG len;

              if (statistics.numroutes == 0)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, ("No IPv4 routes available"));
                  continue;
                }

              /* Query IP Forward Table */
              route_table = ssh_calloc(statistics.numroutes, 
                                       sizeof(*route_table));
              if (route_table == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, 
                            ("Failed to allocate memory for IPv4 "
                             "route table query"));
                  status = FALSE;
                  continue;
                }

              len = statistics.numroutes * sizeof(*route_table);
              status = 
                ssh_tcp_query_information_ex(device,
                                             entity_id->tei_entity,
                                             entity_id->tei_instance,
                                             INFO_CLASS_PROTOCOL,
                                             INFO_TYPE_PROVIDER,
                                             SSH_IP4_MIB_ROUTETABLE_ENTRY_ID,
                                             route_table, &len);
              for (j = 0; 
                   (status == TRUE) && (j < len / sizeof(*route_table)); 
                   j++)
                {
                  SSH_IP4_FORWARD route = &route_table[j];
                  size_t route_size = sizeof(*decoded_copy);
                  size_t old_size = num_routes * route_size;
                  size_t new_size = old_size + route_size;
                  SshIpdevRouteInfo old_routes = decoded_copy;

                  decoded_copy = ssh_realloc(old_routes, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                               ("Failed to allocate memory for IPv4 route."));
                      ssh_free(old_routes);
                      status = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv4 route %u: -----", num_routes));
                  ssh_ipdev_ip4_decode_route(&decoded_copy[num_routes],
                                             route);
                  num_routes++;
                }

              ssh_free(route_table);
            }
        }

      ssh_free(entity_id_list);
    }

  if (status != FALSE)
    {
      route_list->table = decoded_copy;
      route_list->num_items = num_routes;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv4 route table!"));
      ssh_free(decoded_copy);
    }

  return status;  
}


static Boolean
ssh_ipdev_ioctl_request(SshDeviceIoContext io_ctx,
                        SshUInt32 ioctl_code,
                        void *req,
                        SshUInt32 req_len,
                        void *data,
                        SshUInt32 data_len,
                        SshUInt32 *bytes_read)
{
  SshDeviceIoRequestStruct ioctl_req;

  SSH_ASSERT(io_ctx != NULL);

  RtlZeroMemory(&ioctl_req, sizeof(ioctl_req));
  ioctl_req.ioctl_code = ioctl_code;
  ioctl_req.internal_device_control = FALSE;
  ioctl_req.input_buffer = req,
  ioctl_req.input_buff_len = req_len;
  ioctl_req.output_buffer = data;
  ioctl_req.output_buff_len = data_len; 
  ioctl_req.output_size_return = bytes_read;

  if (NT_SUCCESS(ssh_device_ioctl_request(io_ctx, &ioctl_req)))
    return TRUE;
  else
    return FALSE;
}


static void
ssh_ipdev_ioctl_timeout(SshIoCompletion ctx)
{
  IoCancelIrp(ctx->irp);

  if (ctx->close_on_completion)
    {
      ctx->close_on_completion = FALSE;
      ssh_device_close(ctx->io_ctx);
    }
}


static NTSTATUS
ssh_ipdev_ioctl_completion_routine(PDEVICE_OBJECT device,
                                   PIRP irp,
                                   SshIoCompletion context)
{
  PIO_STACK_LOCATION irp_sp = IoGetNextIrpStackLocation(irp);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("I/O completion status = 0x%08X", irp->IoStatus.Status));

  /* If the Cancel flag is set, we are currently cancelling the IRP from
     the timeout callback. */
  if (!irp->Cancel)
    ssh_kernel_timeout_cancel(ssh_ipdev_ioctl_timeout, context);

  switch (irp_sp->Parameters.DeviceIoControl.IoControlCode & 0x00000003)
    {
    case METHOD_BUFFERED:
      ssh_free(irp->AssociatedIrp.SystemBuffer);
      irp->AssociatedIrp.SystemBuffer = NULL;
      irp_sp->Parameters.DeviceIoControl.InputBufferLength = 0;
      break;

    default:
      /* Currently we have support for buffered I/O requests only */
      SSH_NOTREACHED;
      break;
    }

  if (context)
    {
      Boolean success;
      SshIPDevice ip_dev = context->ip_dev;

      if (NT_SUCCESS(irp->IoStatus.Status))
        success = TRUE;
      else
        success = FALSE;

      SSH_ASSERT(ip_dev != NULL);
      InterlockedDecrement(&ip_dev->requests_pending);

      /* OK, we don't normally want to execute the callback directly from
         I/O completion routine, so let's try use work item queue to
         actually execute the callback... */
      if (context->callback != NULL_FNPTR)
        {
          SshInterceptor interceptor = ip_dev->interceptor;

          SSH_ASSERT(interceptor != NULL); 

          if (!ssh_ndis_wrkqueue_queue_raw_item(interceptor->work_queue,
                                                context->callback,
                                                SSH_WORKQUEUE_FN_2_ARGS,
                                                success,
                                                context->context))
            {
              /* Failed, so we need to execute the callback directly */
              (*context->callback)(success, context->context);
            }
        }

      if (context->close_on_completion == TRUE)
	{
	  context->close_on_completion = FALSE;
	  ssh_device_close(context->io_ctx);
	}

      ssh_free(context);
    }

  IoFreeIrp(irp);

  return STATUS_MORE_PROCESSING_REQUIRED;
}


static void
ssh_ipdev_ioctl_request_send(SshIPDevice ip_dev,
                             SshDeviceIoContext io_ctx,
                             SshUInt32 ioc_code,
                             void *req,
                             SshUInt32 req_len,
                             SshUInt32 timeout,
                             SshIPDeviceCompletionCB callback,
                             Boolean close_on_completion,
                             void *context)
{
  PIO_STACK_LOCATION irp_sp;
  SshIoCompletion completion_ctx = NULL;
  VOID *data = NULL;
  PIRP irp = NULL;

  completion_ctx = ssh_calloc(1, sizeof(*completion_ctx));
  if (completion_ctx == NULL)
    { 
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate I/O completion context"));
      goto failed;
    }
  
  completion_ctx->ip_dev = ip_dev;
  completion_ctx->callback = callback;
  completion_ctx->context = context;
  completion_ctx->close_on_completion = close_on_completion;
  completion_ctx->io_ctx = io_ctx;
  
  if (req_len > 0)
    {
      data = ssh_malloc(req_len);
      if (data == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to allocate memory for IOCTL request"));
          goto failed;
        }
    }

  irp = IoAllocateIrp((CCHAR)(io_ctx->dev_obj->StackSize + 1), FALSE);
  if (irp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate IRP"));
      goto failed;
    }

  completion_ctx->irp = irp;

  if (data)
    memcpy(data, req, req_len);

  irp_sp = IoGetNextIrpStackLocation(irp);
  irp_sp->DeviceObject = io_ctx->dev_obj;
  irp_sp->FileObject = io_ctx->file_obj;
  irp_sp->MajorFunction = IRP_MJ_DEVICE_CONTROL;
  irp_sp->Parameters.DeviceIoControl.IoControlCode = ioc_code;
  irp_sp->Parameters.DeviceIoControl.InputBufferLength = req_len;

  switch (ioc_code & 0x00000003)
    {
    case METHOD_BUFFERED:
      irp->AssociatedIrp.SystemBuffer = data;
      break;

    default:
      /* Currently we have support for buffered I/O requests only */
      SSH_NOTREACHED;
      break;
    }

  IoSetCompletionRoutine(irp, ssh_ipdev_ioctl_completion_routine,
                         completion_ctx, TRUE, TRUE, TRUE);

  InterlockedIncrement(&ip_dev->requests_pending);
  if (InterlockedCompareExchange(&ip_dev->suspend_count, 0, 0) == 0)
    {
      ssh_kernel_timeout_register(timeout, 0, ssh_ipdev_ioctl_timeout, 
                                  completion_ctx);
      if (IoCallDriver(io_ctx->dev_obj, irp) == STATUS_PENDING)
        SSH_DEBUG(SSH_D_NICETOKNOW, ("IoCallDriver left IRP pending."));
        
      /* 'requests_pending' is decremented in I/O completion routine */
      return;
    }
  
  /* Ok, we did not send the IRP, close the device and
     free all extra resources we've allocated. . */
  if (close_on_completion == TRUE)
    ssh_device_close(io_ctx);

  if (data)
    ssh_free(data);
  ssh_free(completion_ctx);

  IoFreeIrp(irp);
  if (callback)
    (*callback)(FALSE, context);

  InterlockedDecrement(&ip_dev->requests_pending);
  return;

 failed:

  SSH_DEBUG(SSH_D_FAIL, ("Failed to send device IOCTL request!"));

  if (data)
    ssh_free(data);
  ssh_free(completion_ctx);

  if (irp)
    IoFreeIrp(irp);

  if (callback)
    (*callback)(FALSE, context);
}


/*--------------------------------------------------------------------------
  Makes a TDI Extended Set Information call.
  --------------------------------------------------------------------------*/
static void
ssh_tcp_set_information_ex(SshIPDevice device,
                           ULONG entity,
                           ULONG instance,
                           ULONG info_class,
                           ULONG info_type,
                           ULONG id,
                           VOID *data,
                           ULONG data_len,
                           SshIPDeviceCompletionCB callback,
                           void *context)
{
  TCP_REQUEST_SET_INFORMATION_EX *req;
  SshIPDeviceContext ctx = device->context;
  ULONG req_size;

  SSH_ASSERT(ctx != NULL);

  req_size = sizeof(TCP_REQUEST_SET_INFORMATION_EX) + data_len - 1;
  req = ssh_calloc(1, req_size);
  if (req == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate memory for IOCTL request"));

      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  req->ID.toi_entity.tei_entity = entity;
  req->ID.toi_entity.tei_instance = instance;
  req->ID.toi_class = info_class;
  req->ID.toi_type = info_type;
  req->ID.toi_id = id;
  req->BufferSize = data_len;
  RtlCopyMemory(req->Buffer, data, data_len);

  ssh_ipdev_ioctl_request_send(device, 
                               &ctx->stack_device,
                               IOCTL_TCP_SET_INFORMATION_EX, 
                               req, req_size,
                               SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                               callback, FALSE, context);
}


static Boolean
ssh_open_ipv4_device_for_write(SshIPDevice device,
                               SshDeviceIoContext io_ctx)
{
  SshDeviceIoOpenParamsStruct open_params;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(io_ctx != NULL);

  RtlZeroMemory(&open_params, sizeof(open_params));
  open_params.write_access = TRUE;
  open_params.exclusive_access = FALSE;
  open_params.disable_count_ptr = &device->suspend_count;
  open_params.requests_pending_ptr = &device->requests_pending;
  open_params.default_timeout = SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT;

  return (ssh_device_open(io_ctx, L"\\Device\\Ip", &open_params));
}


static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex system_idx,
                                 SshAddressCtx *ctx_return)
{
  SshIpdevAddressInfo addr_table;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ctx_return != NULL);

  ssh_kernel_rw_mutex_lock_read(&device->addr_lock);
  addr_table = (SshIpdevAddressInfo)device->addrs;

  for (i = 0; i < device->caddr; i++)
    {
      SshIpdevAddressInfo addr = &addr_table[i];

      if (addr->system_idx == system_idx)
        {
          *ctx_return = (SshAddressCtx)addr->address_id;
          ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

          return TRUE;
        }
    }

  ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

  return FALSE;
}


static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params)
{
  /* Just a dummy, since this configure is not supported 
     on XP... etc..  at the moment. Returns always success. */
  return TRUE;
}


static void
ssh_ipdev_ip4_clear_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context)
{
  SshDeviceIoContext io_ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  io_ctx = ssh_calloc(1, sizeof(*io_ctx));
  if (io_ctx == NULL)
    { 
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate I/O context"));
      goto failed;
    }

  if (ssh_open_ipv4_device_for_write(device, io_ctx))
    {
      SSH_IP4_SET_ADDRESS_REQ_STRUCT clear_req;

#pragma warning(disable : 4311)
      clear_req.addr_id = (SshUInt32)addr_ctx;
#pragma warning(default : 4311)
      clear_req.unknown = 0x77E8;

      RtlZeroMemory(clear_req.addr, sizeof(clear_req.addr));
      RtlZeroMemory(clear_req.mask, sizeof(clear_req.mask));
      clear_req.mask[3] = 0xFF;

      /* Clear address */
      ssh_ipdev_ioctl_request_send(device, io_ctx,
                                   IOCTL_IP_SET_ADDRESS,
                                   &clear_req, sizeof(clear_req),
                                   SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                                   callback, TRUE, context);
    }
  else
    {
      ssh_free(io_ctx);

    failed:
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);
    }
}


static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  SshDeviceIoContext io_ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != 0);
  SSH_ASSERT(ip != NULL);

  io_ctx = ssh_calloc(1, sizeof(*io_ctx));
  if (io_ctx == NULL)
    { 
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate I/O context"));
      goto failed;
    }

  if (ssh_open_ipv4_device_for_write(device, io_ctx))
    {
      SSH_IP4_SET_ADDRESS_REQ_STRUCT set_req;

      /* Set new address */
      RtlZeroMemory(&set_req, sizeof(set_req));
      SSH_IP4_ENCODE(ip, set_req.addr);
      ssh_ip_net_mask_from_prefix_len(ip->mask_len, set_req.mask, 4);
#pragma warning(disable : 4311)
      set_req.addr_id = (SshUInt32)addr_ctx;
#pragma warning(default : 4311)
      set_req.unknown = 0;

      ssh_ipdev_ioctl_request_send(device, io_ctx,
                                   IOCTL_IP_SET_ADDRESS,
                                   &set_req, sizeof(set_req),
                                   SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                                   callback, TRUE, context);
    }
  else
    {
      ssh_free(io_ctx);

    failed:
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);
    }
}


static void
ssh_ipdev_ip4_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  SshDeviceIoContextStruct io_ctx;
  BOOLEAN status = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_ip4dev_default_add_address()"));

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(ctx_return != NULL);

  /* Try to open IP device object. This time we communicate with IP device,
     not the TCP device we have already opened. */
  if (ssh_open_ipv4_device_for_write(device, &io_ctx))
    {
      SSH_IP4_ADD_ADDRESS_REQ_STRUCT request;
      SSH_IP4_ADD_ADDRESS_RESP_STRUCT response;
      SshAdapter adapter;
      ULONG bytes_read;
      SshUInt16 name_len;

      adapter = ssh_adapter_ref_by_ifnum(device->interceptor, ifnum);
      if (adapter)
        {
          /* Add space for "TCPIP_" */
          name_len = adapter->orig_name.Length + 6 * sizeof(WCHAR);

          RtlZeroMemory(&request, sizeof(request));

          request.addr_id = 0xFFFF;
          request.unknown = 0;
          request.device_name.Length = name_len;
          request.device_name.MaximumLength = sizeof(request.buffer);
          request.device_name.Buffer = (unsigned short *)&(request.buffer);
          /* Adapter's original name is in format "\Device\{...}". We need to
             just add "TCPIP_" for the "magic" to happen... */
          SSH_ASSERT((name_len +
                      sizeof(UNICODE_NULL)) <= sizeof(request.buffer));
          memcpy(&(request.device_name.Buffer[6]),
                 adapter->orig_name.Buffer, adapter->orig_name.Length);
          memcpy(request.device_name.Buffer, L"\\DEVICE\\TCPIP_", 28);

          SSH_IP4_ENCODE(ip, request.addr);
          ssh_ip_net_mask_from_prefix_len(ip->mask_len, request.mask, 4);

          RtlZeroMemory(&response, sizeof(response));

          /* Retrieve corresponding DEVICE_OBJECT */
          if (ssh_ipdev_ioctl_request(&io_ctx, 
                                      IOCTL_IP_ADD_ADDRESS,
                                      &request, sizeof(request),
                                      &response, sizeof(response), 
                                      &bytes_read))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("IOCTL_IP_ADD_ADDRESS request succeeded "
                         "(%u bytes returned).", bytes_read));

              if (bytes_read == sizeof(response))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("IP device returned IP address ID %u",
                             response.addr_id));

                  *ctx_return = (SshAddressCtx)response.addr_id;

                  status = TRUE;
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Unknown response from IP device!"));
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL, ("IOCTL_IP_ADD_ADDRESS request failed!"));
            }

          ssh_adapter_release(adapter);
        }

      ssh_device_close(&io_ctx);
    }

  if (callback != NULL_FNPTR)
    (*callback)(status, context);
}


static void
ssh_ipdev_ip4_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context)
{
  SshDeviceIoContext io_ctx;
  BOOLEAN status = FALSE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  io_ctx = ssh_calloc(1, sizeof(*io_ctx));
  if (io_ctx == NULL)
    { 
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate I/O context"));
      goto failed;
    }

  /* Try to open IP device object. This time we communicate with IP device,
     not the TCP device we have already opened. */
  if (ssh_open_ipv4_device_for_write(device, io_ctx))
    {
      SSH_IP4_DEL_ADDRESS_REQ_STRUCT request;

      RtlZeroMemory(&request, sizeof(request));
#pragma warning(disable : 4311)
      request.addr_id = (SshUInt32)addr_ctx;
#pragma warning(default : 4311)

      ssh_ipdev_ioctl_request_send(device, io_ctx,
                                   IOCTL_IP_DELETE_ADDRESS,
                                   &request, sizeof(request),
                                   SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                                   callback, TRUE, context);
    }
  else
    {
      ssh_free(io_ctx);

    failed:
      if (callback != NULL_FNPTR)
        (*callback)(status, context);
    }
}


static void
ssh_ipdev_ip4_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context)
{
  SSH_IP4_FORWARD_STRUCT ip_ri;

  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));

  SSH_IP4_ENCODE(&route->dest, &ip_ri.dest);
  SSH_IP4_ENCODE(&route->nm, &ip_ri.mask);
  SSH_IP4_ENCODE(&route->gw, &ip_ri.next_hop);
  ip_ri.if_index = route->system_idx;
  ip_ri.type = 3;       /* Add */
  ip_ri.protocol = 3;
  ip_ri.policy = 0xFFFFFFFF;
  ip_ri.metric1 = route->metric;

  /* Initialize unused fields to zero */
  ip_ri.metric2 =
  ip_ri.metric3 =
  ip_ri.metric4 =
  ip_ri.metric5 =
  ip_ri.unknown1 = 0;

  ssh_tcp_set_information_ex(device, CL_NL_ENTITY, 0,
                             INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER,
                             SSH_IP4_MIB_ROUTETABLE_ENTRY_ID,
                             &ip_ri, sizeof(ip_ri),
                             callback, context);
}


static void
ssh_ipdev_ip4_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context)
{
  SSH_IP4_FORWARD_STRUCT ip_ri;

  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));

  SSH_IP4_ENCODE(&route->dest, &ip_ri.dest);
  SSH_IP4_ENCODE(&route->nm, &ip_ri.mask);
  SSH_IP4_ENCODE(&route->gw, &ip_ri.next_hop);
  ip_ri.if_index = route->system_idx;
  ip_ri.type = 2; /* Remove */

  ssh_tcp_set_information_ex(device, CL_NL_ENTITY, 0,
                             INFO_CLASS_PROTOCOL,
                             INFO_TYPE_PROVIDER,
                             SSH_IP4_MIB_ROUTETABLE_ENTRY_ID,
                             &ip_ri, sizeof(ip_ri),
                             callback, context);
}


#if defined (WITH_IPV6)

static Boolean
ssh_ipdev_ip6_query_interfaces(SshIPDevice device,
                               SshIpdevInterfaceList if_list)
{
  SshIpdevInterfaceInfo decoded_copy = NULL;
  ULONG num_ifs = 0;
  Boolean st = FALSE;
  SshIPDeviceContext ctx = device->context;
  unsigned int ioctl_counter;

  SSH_ASSERT(ctx != NULL);

  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      SSH_IP6_IF_IDENTIFIER_STRUCT id;
      SSH_IP6_IF_STRUCT ip6_if;
      ULONG ioctl_code;
      Boolean query_status;
      ULONG bytes_read = 0;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 interfaces..."));
          ioctl_code = IOCTL_IPV6_QUERY_INTERFACE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 interfaces..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_INTERFACE;
        }

      /* Initialize the request using index -1 and all-zero GUID */
      RtlZeroMemory(&id, sizeof(id));
      id.index = -1;

      RtlZeroMemory(&ip6_if, sizeof(ip6_if));

      /* (1) Query the 1st interface identifier (index + GUID) */
      query_status = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                             ioctl_code, 
                                             &id, sizeof(id),
                                             &ip6_if, sizeof(ip6_if), 
                                             &bytes_read);

      /* Check results */
      if (query_status == FALSE)
        {
          if (ioctl_code == IOCTL_IPV6_QUERY_INTERFACE)
            {
              if (bytes_read < sizeof(SSH_IP6_IF_IDENTIFIER_STRUCT))
                {
                  SSH_DEBUG(SSH_D_FAIL, 
                            ("Failed to query first non-persistent "
                             "IPv6 interface"));
                  return FALSE;
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No persistent IPv6 interfaces; continuing..."));
              goto interfaces_read;
            }
        }

      /* (2) Query interface info for all IPv6 interfaces */
      st = query_status;
      while ((st != FALSE) && (ip6_if.next_id.index != (ULONG)-1))
        {
          id = ip6_if.next_id;

          st = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                       ioctl_code,
                                       &id, sizeof(id),
                                       &ip6_if, sizeof(ip6_if),
                                       &bytes_read);
          if (st != FALSE)
            {
              size_t if_struct_size = sizeof(*decoded_copy);
              size_t old_size = num_ifs * if_struct_size;
              size_t new_size = old_size + if_struct_size;
              SshIpdevInterfaceInfo old_ifs = decoded_copy;

              decoded_copy = ssh_realloc(old_ifs, old_size, new_size);
              if (decoded_copy == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                           ("Failed to allocate memory for IPv6 interface!"));
                  ssh_free(old_ifs);
                  st = FALSE;
                  break;
                }

              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("----- IPv6 interface %u: -----", num_ifs));
              ssh_ipdev_ip6_decode_interface(&decoded_copy[num_ifs], &ip6_if);
              num_ifs++;
            }
        }
    }

 interfaces_read:
  if (st != FALSE)
    {
      if_list->table = decoded_copy;
      if_list->num_items = num_ifs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to read IPv6 interface information."));
      ssh_free(decoded_copy);
    }

  return st;
}


/*--------------------------------------------------------------------------
  Retrieves the IPv6 network address information from TCP/IPv6 stack.
  --------------------------------------------------------------------------*/
static Boolean
ssh_ipdev_ip6_query_addresses(SshIPDevice device,
                              SshIpdevAddressList addr_list)
{
  SshIpdevInterfaceListStruct if_list;
  SshIpdevAddressInfo decoded_copy = NULL;
  SshUInt32 num_addrs = 0;
  Boolean st = FALSE;
  unsigned int ioctl_counter;
  SshIPDeviceContext ctx = device->context;

  SSH_ASSERT(ctx != NULL);

  RtlZeroMemory(&if_list, sizeof(if_list));
  if (!ssh_ipdev_ip6_query_interfaces(device, &if_list))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to query IPv6 interfaces"));
      return FALSE;
    }

  /* Query address info for all IPv6 addresses */
  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      SshIpdevInterfaceInfo ifs = (SshIpdevInterfaceInfo)if_list.table;
      ULONG ioctl_code;
      unsigned int i;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 addresses..."));
          ioctl_code = IOCTL_IPV6_QUERY_ADDRESS;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 addresses..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_ADDRESS;
        }

      for (i = 0; i < if_list.num_items; i++)
        {
          SSH_IP6_ADDR_ID_STRUCT req;
          SSH_IP6_ADDR_STRUCT addr;
          ULONG bytes_read = 0;
          SshIpdevInterfaceInfo ip6_if = &ifs[i];
          Boolean query_st;

          /* Query first address ID (interface index + GUID + IPv6 address) */
          SSH_ASSERT(ip6_if->id.id_type == SSH_IF_ID_GUID);
          req.if_id.index = ip6_if->system_idx;
          req.if_id.guid  = ip6_if->id.u.guid;
          RtlCopyMemory(req.addr, 
                        SSH_IP6_UNDEFINED_ADDR, 
                        SSH_MAX_IP6_ADDR_LEN);

          query_st = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                             ioctl_code,
                                             &req, sizeof(req),
                                             &addr, sizeof(addr), 
                                             &bytes_read);

          if ((query_st == FALSE)
              && (ioctl_code == IOCTL_IPV6_PERSISTENT_QUERY_ADDRESS))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("No persistent IPv6 addresses; continuing..."));
              goto addresses_read;
            }

          /* Query all addresses of specified interface */
          st = query_st;
          while ((st != FALSE) &&
                 (bytes_read >= sizeof(SSH_IP6_ADDR_ID_STRUCT)) &&
                 (RtlEqualMemory(addr.next_addr.addr,
                                 SSH_IP6_UNDEFINED_ADDR,
                                 SSH_MAX_IP6_ADDR_LEN) == FALSE))
            {
              req = addr.next_addr;

              st = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                           ioctl_code,
                                           &req, sizeof(req),
                                           &addr, sizeof(addr), 
                                           &bytes_read);
              if ((st != FALSE) && (bytes_read >= sizeof(addr)))
                {
                  size_t addr_size = sizeof(*decoded_copy);
                  size_t old_size = num_addrs * addr_size;
                  size_t new_size = old_size + addr_size;
                  SshIpdevAddressInfo old_addrs = decoded_copy;

                  decoded_copy = ssh_realloc(old_addrs, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Failed to allocate memory for IPv6 "
                                 "addresses!"));
                      ssh_free(old_addrs);
                      st = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv6 address %u: -----", num_addrs));
                  ssh_ipdev_ip6_decode_address(&decoded_copy[num_addrs], 
                                               &addr);
                  num_addrs++;
                }
            }
        }
    }

  /* Process results */
 addresses_read:
  ssh_free(if_list.table);

  if (st != FALSE)
    {
      addr_list->table = decoded_copy;
      addr_list->num_items = num_addrs;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to read IPv6 address information."));
      ssh_free(decoded_copy);
    }

  return st;
}


/*--------------------------------------------------------------------------
  Retrieves the IPv6 routing information from TCP/IPv6 stack.
  --------------------------------------------------------------------------*/
static Boolean
ssh_ipdev_ip6_query_routes(SshIPDevice device,
                           SshIpdevRouteList route_list)
{
  Boolean st = FALSE;
  SshIpdevRouteInfo decoded_copy = NULL;
  ULONG num_routes = 0;
  SshIPDeviceContext ctx = device->context;
  unsigned int ioctl_counter;

  SSH_ASSERT(ctx != NULL);

  for (ioctl_counter = 0; ioctl_counter < 2; ioctl_counter++)
    {
      struct SSH_IP6_ROUTE_QUERY_REC req;
      SSH_IP6_ROUTE_STRUCT route_info;
      ULONG required_size;
      ULONG bytes_read = 0;
      ULONG ioctl_code;
      Boolean query_st;

      if (ioctl_counter == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying non-persistent IPv6 routes..."));
          ioctl_code = IOCTL_IPV6_QUERY_ROUTE_TABLE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Querying persistent IPv6 routes..."));
          ioctl_code = IOCTL_IPV6_PERSISTENT_QUERY_ROUTE_TABLE;
        }
  
      /* Query the 1st route table entry index */
      RtlZeroMemory(&req, sizeof(req));
      RtlZeroMemory(&route_info, sizeof(route_info));
      required_size = sizeof(req);
      query_st = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                         ioctl_code,
                                         &req, sizeof(req),
                                         &route_info, sizeof(route_info),
                                         &bytes_read);

      if ((query_st == FALSE)
          && (ioctl_code == IOCTL_IPV6_PERSISTENT_QUERY_ROUTE_TABLE))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("No persistent IPv6 addresses; continuing..."));
          goto routes_read;
        }

      /* Query route info for all routing entries */
      st = query_st;
      req = route_info.route;
      while ((st != FALSE) &&
             (req.if_id.index != 0L) &&
             (bytes_read == required_size))
        {
          RtlZeroMemory(&route_info, sizeof(route_info));
          required_size = sizeof(route_info);
          st = ssh_ipdev_ioctl_request(&ctx->stack_device,
                                       ioctl_code,
                                       &req, sizeof(req),
                                       &route_info, sizeof(route_info),
                                       &bytes_read);

          if (st != FALSE)
            {
              struct SSH_IP6_ROUTE_QUERY_REC next_req;

              next_req = route_info.route;

              if (req.if_id.index != 0)
                {
                  size_t route_info_size = sizeof(*decoded_copy); 
                  size_t old_size = num_routes * route_info_size;
                  size_t new_size = old_size + route_info_size;
                  SshIpdevRouteInfo old_routes = decoded_copy;

                  /* Collect results into route array */
                  route_info.route = req;
                  decoded_copy = ssh_realloc(old_routes, old_size, new_size);
                  if (decoded_copy == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                               ("Failed to allocate memory for IPv6 route."));
                      ssh_free(old_routes);
                      st = FALSE;
                      break;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("----- IPv6 route %u: -----", num_routes));
                  ssh_ipdev_ip6_decode_route(&decoded_copy[num_routes],
                                             &route_info);
                  num_routes++;
                }

              req = next_req;
            }
        }
    }

  /* Process results */
 routes_read:
  if (st != FALSE)
    {
      route_list->table = decoded_copy;
      route_list->num_items = num_routes;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to read IPv6 route table."));
      ssh_free(decoded_copy);
    }

  return st;
}


static void
ssh_ipdev_ip6_add_address(SshIPDevice device,
                          SshIFIndex system_idx,
                          SshInterceptorIfnum ifnum,
                          SshIpAddr ip,
                          SshAddressCtx *ctx_return,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  SSH_IP6_ADDR_UPDATE request;
  ULONG bytes_read;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(ctx_return != NULL);

  ctx = device->context;

  request = ssh_calloc(1, sizeof(*request));
  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate memory for I/O request"));
      goto add_failed;
    }

  request->if_id.index = system_idx;
  /* Interface GUID does not seem to be defined in this request, only
     interface index must be correct. (I guess it's this way easier also
     for Microsoft's own user mode tools IPV6.EXE / NETSH.EXE.) */
  SSH_IP6_ENCODE(ip, request->addr);
  request->type = 0;
  request->prefix_conf = 1;
  request->interface_id_conf = 1;
  request->preferred_life_time = 0xFFFFFFFF;
  request->valid_life_time     = 0xFFFFFFFF;

  if (ssh_ipdev_ioctl_request(&ctx->stack_device,
                              IOCTL_IPV6_PERSISTENT_UPDATE_ADDRESS,
                              request, sizeof(*request),
                              NULL, 0, &bytes_read))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IPv6 address %@ successfully added.",
                 ssh_ipaddr_render, ip));

      *ctx_return = request;

      if (callback != NULL_FNPTR)
        (*callback)(TRUE, context);

      return;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to add IPv6 address %@!", ssh_ipaddr_render, ip));

      ssh_free(request);
    }

 add_failed:

  *ctx_return = NULL;

  if (callback != NULL_FNPTR)
    (*callback)(FALSE, context);
}


static void
ssh_ipdev_ip6_delete_address(SshIPDevice device,
                             SshAddressCtx addr_ctx,
                             SshIPDeviceCompletionCB callback,
                             void *context)
{
  SSH_IP6_ADDR_UPDATE request = addr_ctx;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  ctx = device->context;

  /* Deletion of IPv6 address is easy. Just set the lifetimes to zero, and
     the address will dissappear... */
  request->preferred_life_time = 0;
  request->valid_life_time = 0;

  ssh_ipdev_ioctl_request_send(device,
                               &ctx->stack_device,
                               IOCTL_IPV6_PERSISTENT_UPDATE_ADDRESS,
                               request, sizeof(*request),
                               SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                               callback, FALSE, context);
}


/*--------------------------------------------------------------------------
  Inserts the specified route into a routing table.
  --------------------------------------------------------------------------*/
static void
ssh_ipdev_ip6_add_route(SshIPDevice device,
                        SshIPRoute route,
                        SshIPDeviceCompletionCB callback,
                        void *context)
{
  SSH_IP6_ROUTE_STRUCT request;
  unsigned int len;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));

  ctx = device->context;

  RtlZeroMemory(&request, sizeof(request));
  SSH_IP_ENCODE(&route->dest, &request.route.dest, len);
  request.route.prefix_len = route->nm_len;
  request.route.if_id.index = route->system_idx;
  SSH_IP_ENCODE(&route->gw, &request.route.next_hop, len);
  request.site_prefix_len = 0;
  request.valid_life_time = -1;     /* infinite */
  request.preferred_life_time = -1; /* infinite */
  request.preference = 0;
  request.type = 0x3;
  request.publish = 1;
  request.age = 1;

  ssh_ipdev_ioctl_request_send(device, 
                               &ctx->stack_device,
                               IOCTL_IPV6_PERSISTENT_UPDATE_ROUTE,
                               &request, sizeof(request),
                               SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                               callback, FALSE, context);
}


/*--------------------------------------------------------------------------
  Removes the specified route from a routing table.
  --------------------------------------------------------------------------*/
static void
ssh_ipdev_ip6_remove_route(SshIPDevice device,
                           SshIPRoute route,
                           SshIPDeviceCompletionCB callback,
                           void *context)
{
  SSH_IP6_ROUTE_STRUCT request;
  unsigned int len;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));
  
  ctx = device->context;

  memset(&request, 0, sizeof(request));
  SSH_IP_ENCODE(&route->dest, &request.route.dest, len);
  request.route.prefix_len = route->nm_len;
  request.route.if_id.index = route->system_idx;
  SSH_IP_ENCODE(&route->gw, &request.route.next_hop, len);
  request.site_prefix_len = 0;
  request.valid_life_time = 0;
  request.preferred_life_time = 0;
  request.preference = 0;
  request.type = 0x3;
  request.publish = 0;
  request.age = 0;

  ssh_ipdev_ioctl_request_send(device, 
                               &ctx->stack_device,
                               IOCTL_IPV6_PERSISTENT_UPDATE_ROUTE,
                               &request, sizeof(request),
                               SSH_IPDEVICE_DEFAULT_IRP_TIMEOUT,
                               callback, FALSE, context);
}
#endif /* WITH_IPV6 */

