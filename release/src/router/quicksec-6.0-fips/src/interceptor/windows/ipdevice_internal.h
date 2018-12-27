/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for platform dependent part of IP protocol stack
   interface.
*/

#ifndef SSH_IPDEVICE_INTERNAL_H
#define SSH_IPDEVICE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#define SSH_DEBUG_MODULE "SshInterceptorIpDevice"

#define SSH_MAX_IP6_ADDR_LEN            16     /* [8 bit] */

/*--------------------------------------------------------------------------
  Type definitions
  --------------------------------------------------------------------------*/
typedef struct SshIpdevRouteInfoRec
{
  /* System specific network interface identifier */
  SshIFIndex system_idx;

  /* Route type (direct or indirect) */
  UCHAR type;

  /* MTU for interface */
  size_t mtu;

  /* Destination */
  SshIpAddrStruct dest;

  /* Network mask and it's length */
  SshIpAddrStruct nm;
  unsigned long nm_len;

  /* Forwarding IP Address */
  SshIpAddrStruct gw;

  /* Metric */
  ULONG metric;
} SshIpdevRouteInfoStruct, *SshIpdevRouteInfo;


typedef struct SshIpdevInterfaceInfoRec
{
  /* System specific network interface identifier */
  SshIFIndex system_idx;

  /* Interface MTU */
  SshUInt32 mtu;

  /* MAC address */
  unsigned char media_address[SSH_ADAPTER_MEDIA_ADDR_LEN_MAX]; 
  SshUInt16 media_addr_len;           

  /* Protocol stack (IPv4 vs. IPv6) specific interface identifiers */
  SshIPInterfaceIDStruct id;

  /* Flags: */
  unsigned int is_loopback : 1;       /* this is a loopback interface? */
  unsigned int has_media_address : 1; /* 'media_address' present */
  unsigned int has_mtu : 1;           /* MTU present */
} SshIpdevInterfaceInfoStruct, *SshIpdevInterfaceInfo;


typedef struct SshIpdevAddressInfoRec
{
  /* Decoded interface address */
  SshInterfaceAddressStruct if_addr;

  /* System specific network interface identifier */
  SshIFIndex system_idx;

  /* System specific address identifier */
  SshUInt32 address_id;

  /* Address type or state */
  SshUInt32 type;

  /* Creation timestamp */
  SshUInt64 timestamp;

  /* Duplicate address detection state */
  SshUInt32 dad_state;

  /* Lifetimes for the address */
  SshUInt32 valid_lifetime;
  SshUInt32 preferred_lifetime;

  /* Maximum re-assembly size */
  SshUInt32 reasm_size;

} SshIpdevAddressInfoStruct, *SshIpdevAddressInfo;


typedef struct SshIpdevInterfaceListRec
{
  /* Number of items in 'table' */
  SshUInt32 num_items;
  /* List of platform dependent IP address structures */
  SshIpdevInterfaceInfo table;
} SshIpdevInterfaceListStruct, *SshIpdevInterfaceList;

typedef struct SshIpdevAddressListRec
{
  /* Number of items in 'table' */
  SshUInt32 num_items;
  /* List of platform dependent IP address structures */
  SshIpdevAddressInfo table;
} SshIpdevAddressListStruct, *SshIpdevAddressList;

typedef struct SshIpdevRouteListRec
{
  /* Number of items in 'table' */
  SshUInt32 num_items;
  /* List of platform dependent IP address structures */
  SshIpdevRouteInfo table;
} SshIpdevRouteListStruct, *SshIpdevRouteList;

/*--------------------------------------------------------------------------
  Platform dependent functions
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Platform dependent initialization function that will be internally called
  from ssh_ipdev_init(). This function is called after the platform
  independent part of SshIPDevice is fully initialized.

  Normally this function replaces at least 'refresh', 'add_address',
  'delete_address', 'add_route' and 'remove_route' functions of SshIPDevice
  object with platform dependent implementations.

  This is mandatory function that must always be implemented in platform 
  dependent code.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_platform_init(SshIPDevice device);

/*--------------------------------------------------------------------------
  Platform dependent uninitialization function that will be internally
  called from ssh_ipdev_uninit(). This function is called before the
  platform independent part of SshIPDevice is uninitialized.

  This is mandatory function that must always be implemented in platform 
  dependent code.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_platform_uninit(SshIPDevice device);

/*--------------------------------------------------------------------------
  Platform dependent function for establishing connection to IPv4/IPv6 
  protocol stack.

  This is mandatory function that must always be implemented in platform 
  dependent code.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_platform_connect(SshIPDevice device);

/*--------------------------------------------------------------------------
  Platform dependent function for closing connection to IPv4/IPv6 protocol 
  stack.

  This is mandatory function that must always be implemented in platform 
  dependent code.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_platform_disconnect(SshIPDevice device);

#if 0
/*--------------------------------------------------------------------------
  Platform dependent route decoding function. The platform dependent route
  having index number 'route_index' in 'route_list' must be converted to 
  platform independent representation and saved to given SshIpdevRouteInfo
  structure 'route'.

  The platform independent code takes care of the concurrency control for
  both 'interface_list' and 'route_list', so ssh_ipdev_decode_route()
  MUST NOT acquire any internal lock of SshIPDevice object.

  This is mandatory function that must always be implemented in platform
  dependent code.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_decode_route(SshIpdevRouteInfo route,
                       SshIpdevInterfaceList interface_list,
                       SshIpdevRouteList route_list,
                       SshUInt32 route_index);

/*--------------------------------------------------------------------------
  Platform dependent interface decoding function. The platform dependent 
  IP interface having index number 'if_index' in 'interface_list' must be 
  converted to platform independent representation and saved to given 
  SshIpdevInterfaceInfo structure 'if_info'.

  The platform independent code takes care of the concurrency control for
  'interface_list', so ssh_ipdev_decode_interface() MUST NOT acquire any 
  internal lock of SshIPDevice object.

  This is mandatory function that must always be implemented in platform
  dependent code.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_decode_interface(SshIpdevInterfaceInfo if_info,
                           SshIpdevInterfaceList interface_list,
                           SshUInt32 if_index);

/*--------------------------------------------------------------------------
  Platform dependent IP address decoding function. The platform dependent 
  IP address structure having index number 'addr_index' in 'addr_list' must 
  be converted to platform independent representation and saved to given 
  SshInterfaceAddress structure 'addr'.

  The platform independent code takes care of the concurrency control for
  'addr_list', so ssh_ipdev_decode_address() MUST NOT acquire any internal 
  locks of SshIPDevice object.

  This is mandatory function that must always be implemented in platform
  dependent code.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_decode_address(SshIpdevAddressInfo addr,
                         SshIpdevAddressList addr_list,
                         SshUInt32 addr_index);

/*--------------------------------------------------------------------------
  Platform dependent function for querying the number of IP addresses the
  specified interface 'iface' currently has. 
 
  The platform independent code takes care of the concurrency control for 
  'address_list', so ssh_ipdev_get_num_addresses() MUST NOT acquire any 
  internal lock of SshIPDevice object.

  This is mandatory function that must always be implemented in platform
  dependent code.
  --------------------------------------------------------------------------*/
SshUInt32
ssh_ipdev_get_num_addresses(SshIPInterface iface,
                            SshIpdevAddressList addr_list);

/*--------------------------------------------------------------------------
  Platform dependent function for querying the IP addresses of the specified 
  interface 'iface'. The interface addresses are stored to 'addr_array' 
  having maximum length of 'max_addrs'. The return value is the number of IP
  addresses actually decoded and copied to 'ipaddr_array'.

 
  The platform independent code takes care of the concurrency control for 
  'address_list', so ssh_ipdev_get_num_addresses() MUST NOT acquire any 
  internal lock of SshIPDevice object.

  This is mandatory function that must always be implemented in platform
  dependent code.
  --------------------------------------------------------------------------*/
SshUInt32
ssh_ipdev_get_addresses(SshIPInterface iface,
                        SshIpdevAddressList address_list,
                        SshIpdevAddressInfo addr_array,
                        SshUInt32 max_addrs);
#endif /* 0 */

#ifdef __cplusplus
}
#endif

#endif /* SSH_IPDEVICE_INTERNAL_H */

