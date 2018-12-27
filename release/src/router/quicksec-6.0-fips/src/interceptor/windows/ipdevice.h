/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the definitions and function prototypes for communicating
   with Microsoft IP and IPv6 protocol stack from a device driver.
*/

#ifndef SSH_IPDEVICE_H
#define SSH_IPDEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SSH_MAX_IF_DESCR_LEN            256

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC

/* IP device identifiers */ 
typedef enum
{
  SSH_DD_ID_UNDEF,
  SSH_DD_ID_IP4,
  SSH_DD_ID_IP6                   
} SshIPDeviceID;

/* IP route types */
#define SSH_IP_ROUTE_UNDEF              0x00
#define SSH_IP_ROUTE_DIRECT             0x01
#define SSH_IP_ROUTE_INDIRECT           0x02

/* Flags for SshIPDeviceRefresh */
#define SSH_IP_CHANGED_INTERFACES       1
#define SSH_IP_CHANGED_ADDRESSES        2
#define SSH_IP_CHANGED_ROUTES           4

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/
  
typedef enum 
{
  SSH_IF_ID_NONE = 0,
  SSH_IF_ID_DESCRIPTION,
  SSH_IF_ID_GUID,
  SSH_IF_ID_LUID,
  SSH_IF_ID_ADAPTER_IFNUM, 
  SSH_IF_ID_SYSTEM_IFNUM 
} SshIPInterfaceIDType;

typedef struct SshIPInterfaceIDRec
{
  SshIPInterfaceIDType id_type;

  union 
  {
    /* Interface identifier for stack */
    struct 
    {
      unsigned char description[SSH_MAX_IF_DESCR_LEN];
      SshUInt32 description_len;
    } d;

    /* GUID used as an interface identifier for stack */
    GUID guid;

    /* 64-bit LUID used as an interface identifier */
    SshUInt64 luid;

    /* Interceptor assigned interface number */
    SshInterceptorIfnum ifnum;

    /* Operating system assigned interface number */
    SshUInt32 system_ifnum;
  } u;

} SshIPInterfaceIDStruct, *SshIPInterfaceID;


#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC

typedef struct SshIPDeviceRec *SshIPDevice;

/* Abstract context for IP addresses */
typedef void *SshAddressCtx;

typedef enum SshIpdevConfigureTypeEnum {
  SSH_IPDEV_CONFIGURE_TYPE_DAD,
  SSH_IPDEV_CONFIGURE_TYPE_MTU,
  SSH_IPDEV_CONFIGURE_TYPE_LINK_LOCAL,
  SSH_IPDEV_CONFIGURE_TYPE_IFACE_METRIC
} SshIpdevConfigureType;

unsigned char SSH_IP6_UNDEFINED_ADDR[];

/* Operating system specific interface identifier */
typedef SshUInt32 SshIFIndex;

/* Descriptor for IP network interface information */
typedef struct SshIPInterfaceRec
{
  /* For book-keeping purposes */
  LIST_ENTRY link;

  /* System specific network interface identifiers */
  SshIFIndex system_idx;

  /* SSH specific network interface identifier */
  SshInterceptorIfnum adapter_ifnum;

  /* Physical address and it's length */
  unsigned char media_addr[SSH_ADAPTER_MEDIA_ADDR_LEN_MAX];
  SshUInt32 media_addr_len;

  /* IP addresses */
  SshUInt32 num_addrs;          
  SshInterfaceAddress addrs;    

  /* Interface MTU */
  size_t mtu;  

  /* Pointer to owner IP device object */
  SshUInt32 owner_device_id;
  SshIPDevice owner;

  /* Protocol stack (IPv4 vs. IPv6) specific identifier */
  SshIPInterfaceIDStruct id;

} SshIPInterfaceStruct, *SshIPInterface;

/* Descriptor for IP network routing information */
typedef struct SshIPRouteRec
{
  /* For book-keeping */
  LIST_ENTRY link;

  /* System specific network interface identifier */
  SshIFIndex system_idx;

  /* Interface LUID */
  SshUInt64 luid;

  /* SSH specific network interface identifier */
  SshInterceptorIfnum ifnum;

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

  /* Pointer to owner IP device object */
  SshIPDeviceID owner_device_id;
  SshIPDevice owner;

} SshIPRouteStruct, *SshIPRoute;

typedef void (__fastcall *SshIPDeviceCompletionCB)(Boolean status,
                                                   void *context);

typedef Boolean (*SshIPDeviceGetList)(SshIPDevice ip_dev, 
                                      PLIST_ENTRY list, 
                                      ULONG *item_cnt_return);

typedef Boolean (*SshIPDeviceQueryInfo)(SshIPDevice ip_dev,
                                        void *info);

typedef void (*SshIPDeviceModifyRouting)(SshIPDevice ip_dev, 
                                         SshIPRoute route,
                                         SshIPDeviceCompletionCB cb,
                                         void *context);

typedef Boolean (*SshIPDeviceFindFirstAddr)(SshIPDevice ip_dev,
                                            SshIFIndex system_idx,
                                            SshAddressCtx *ctx_return);

typedef void (*SshIPDeviceSetAddress)(SshIPDevice ip_dev,
                                      SshAddressCtx addr_ctx,
                                      SshIpAddr ip,
                                      SshIPDeviceCompletionCB cb,
                                      void *context);

typedef void (*SshIPDeviceAddAddress)(SshIPDevice ip_dev,
                                      SshIFIndex system_idx,
                                      SshInterceptorIfnum ifnum,
                                      SshIpAddr ip,
                                      SshAddressCtx *ctx_return,
                                      SshIPDeviceCompletionCB cb,
                                      void *context);

typedef void (*SshIPDeviceDelAddress)(SshIPDevice ip_dev,
                                      SshAddressCtx addr_ctx,
                                      SshIPDeviceCompletionCB cb,
                                      void *context);











/* 
   Currently only 3 types of configuration is supported for
   adapters. These are:

   1. Set Duplicate address detection count. 
      configure_type   = SSH_IPDEV_CONFIGURE_TYPE_DAD
      configure_params = count of Duplicate Address Detection 
                         messages (Type (SshUInt32 *))

   2. Configure adapter MTU.
      configure_type   = SSH_IPDEV_CONFIGURE_TYPE_MTU
      configure_params = mtu size for the adapter 
                         (Type (SshUInt32 *))

   3. Configure LINK LOCAL address behaviour.
      configure_type   = SSH_IPDEV_CONFIGURE_TYPE_LINK_LOCAL
      configure_params = value 0, disable link local address
                         value 1, delayed. See MSDN for more details
                         value 2, always on
                         (Type (SshUInt32 *))
 */
typedef Boolean (*SshIPDeviceConfigure)(SshIPDevice ip_dev,
                                        SshIFIndex system_idx,
                                        SshUInt16 configure_type,
                                        void *configure_params);


/* Descriptor for IP Device structure */
typedef struct SshIPDeviceRec
{
  /* Device ID */
  SshIPDeviceID dev_id;

  /* Pointer to interceptor object */
  SshInterceptor interceptor;

  /* Suspend count; "IP device" is disabled when this is non-zero */
  ULONG suspend_count;

  /* Number of pending requests "IP device" has sent to protocol stack */
  ULONG requests_pending;

  /* TRUE if the interface object has already opened connection to protocol
     stack, otherwise FALSE */
  Boolean connected;

  /* Interface count and platform dependent interface information */
  SshKernelRWMutexStruct if_lock;
  unsigned long cif;
  void *ifs;

  /* Address count and platform dependent address information */
  SshKernelRWMutexStruct addr_lock;
  unsigned long caddr;
  void *addrs;

  /* Route count and platform dependent route information */
  SshKernelRWMutexStruct route_lock;
  unsigned long croute;
  void *routes;

  /* Query functions for interfaces, IP address and routing tables. */
  SshIPDeviceQueryInfo query_interface_list;
  SshIPDeviceQueryInfo query_address_list;
  SshIPDeviceQueryInfo query_route_list;

  /* 'Find first address' function */
  SshIPDeviceFindFirstAddr find_first_address;

  /* 'Clear address' function */
  SshIPDeviceDelAddress clear_address;








  /* 'Set address' function */
  SshIPDeviceSetAddress set_address;

  /* 'Add alias' function */
  SshIPDeviceAddAddress add_address;

  /* 'Remove alias' function */
  SshIPDeviceDelAddress delete_address;

  /* 'Add route' function */
  SshIPDeviceModifyRouting add_route;

  /* 'Remove route' function */
  SshIPDeviceModifyRouting remove_route;

  /* 'Configure' function */
  SshIPDeviceConfigure configure;

  /* Free lists to prevent unnecessary dynamic memory allocations */
  SshKernelMutexStruct free_list_lock;  
  LIST_ENTRY ip_if_free_list;
  LIST_ENTRY route_free_list;

  /* Platform dependent section */
  void *context;
} SshIPDeviceStruct;


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Calculates the prefix length from subnet mask.
  --------------------------------------------------------------------------*/
__inline ULONG
ssh_ip_net_mask_calc_prefix_len(SshIpAddr nm)
{
  int i ,j, c = 0;
  int l = (nm->type == SSH_IP_TYPE_IPV4 ? 4 : 16);

  for (i = 0; i < l; i++)
    {
      for (j = 0; j < 8; j++)
        {
          if ((nm->addr_data[i] >> j) & 0x01) 
            c++;
        }
    }

  return(c);
}

__inline VOID
ssh_ip_net_mask_from_prefix_len(ULONG prefix_len, 
                                UCHAR *mask, 
                                ULONG mask_len_bytes)
{
  ULONG i;

  memset(mask, 0, mask_len_bytes);
  i = 0;
  while (i < (prefix_len / 8))
    {
      mask[i] = 0xFF; 
      i++;
    }

  prefix_len -= i * 8;
  if (prefix_len)
    mask[i] = (UCHAR)(0xFF << (8 - prefix_len));
}

/*--------------------------------------------------------------------------
  ssh_ipdev_init()

  Initializes IP device interface object. This function must be called 
  before any other ssh_ipdev_xxx() functions.
  
  Arguments:
  device - object to be initialized
  interceptor - pointer to interceptor object owning this IP device interface
  dev_id - device identifier (IPv4, or IPv6)
  
  Returns:
  TRUE if IP device interface object was successfully initialized or FALSE
  if an error occurred.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_init(SshIPDevice device,
               SshInterceptor interceptor,
               SshIPDeviceID device_id);

/*--------------------------------------------------------------------------
  ssh_ipdev_uninit()

  Uninitializes IP device interface object. 
  
  Arguments:
  device - object to be uninitialized
  
  Returns:
  -
  --------------------------------------------------------------------------*/
void
ssh_ipdev_uninit(SshIPDevice device);

Boolean
ssh_ipdev_is_connected(SshIPDevice device);

Boolean 
ssh_ipdev_connect(SshIPDevice device);

void
ssh_ipdev_disconnect(SshIPDevice device);

/*--------------------------------------------------------------------------
  Suspends the IP device object
  --------------------------------------------------------------------------*/
void
ssh_ipdev_suspend(SshIPDevice device);

/*--------------------------------------------------------------------------
  Resumes the IP device object
  --------------------------------------------------------------------------*/
void 
ssh_ipdev_resume(SshIPDevice device);

/*--------------------------------------------------------------------------
  ssh_ipdev_route_alloc()

  Allocates a new route structure. 

  Arguments:
  device - SshIPDevice object,

  Return:
  Pointer to SshIPRoute structure or NULL if route could not be allocated.
  --------------------------------------------------------------------------*/
SshIPRoute 
ssh_ipdev_route_alloc(SshIPDevice device);

/*--------------------------------------------------------------------------
  ssh_ipdev_route_free()

  Frees a previously alloced route structure. 

  Arguments:
  route - route structure to be freed.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_route_free(SshIPRoute route);

/*--------------------------------------------------------------------------
  ssh_ipdev_interface_alloc()

  Allocates a new IP interface structure. 

  Arguments:
  device - SshIPDevice object,

  Return:
  Pointer to SshIPInterface structure or NULL if interface could not be 
  allocated.
  --------------------------------------------------------------------------*/
SshIPInterface
ssh_ipdev_interface_alloc(SshIPDevice device);

/*--------------------------------------------------------------------------
  ssh_ipdev_interface_free()

  Frees a previously alloced IP interface structure. 

  Arguments:
  ip_if - interface structure to be freed.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_interface_free(SshIPInterface ip_if);

/*--------------------------------------------------------------------------
  Refreshes IP network (interfaces, addresses and routes) information.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_refresh(SshIPDevice device, SshUInt32 *changed);

/*--------------------------------------------------------------------------
  Returns the IP network interface table.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_get_interface_list(SshIPDevice device,
                             PLIST_ENTRY list,
                             ULONG *if_count_return);

/*--------------------------------------------------------------------------
  Returns the IP network routing table.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_get_route_list(SshIPDevice device,
                         PLIST_ENTRY list,
                         ULONG *route_count_return);

/*--------------------------------------------------------------------------
  Searches for the first IP address of the adapter and returns the associated
  'addres context' in 'ctx_return'.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_find_first_address(SshIPDevice device,
                             SshAdapter adapter,
                             SshAddressCtx *ctx_return);

/*--------------------------------------------------------------------------
  Configures parameters. Returns TRUE on success and FALSE on failure.
  Possible parameters to configure are Duplicate Address Detection retry
  count and MTU. 
  --------------------------------------------------------------------------*/
Boolean 
ssh_ipdev_configure(SshIPDevice ip_dev,
                    SshAdapter adapter,
                    SshUInt16 configure_type,
                    void *configure_params);

/*--------------------------------------------------------------------------
  Clears the IP address specified by the 'address context' previosuly 
  returned by ssh_ipdev_add_address().
  --------------------------------------------------------------------------*/
void
ssh_ipdev_clear_address(SshIPDevice device,
                        SshAddressCtx addr_ctx,
                        SshIPDeviceCompletionCB callback,
                        void *context);

/*--------------------------------------------------------------------------
  Clears/deletes all IP addresses from the specified adapter.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_clear_all_addresses(SshIPDevice device,
                              SshAdapter adapter,
                              SshIPDeviceCompletionCB callback,
                              void *context);

/*--------------------------------------------------------------------------
  Changes the specified IP address.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_set_address(SshIPDevice device,
                      SshAddressCtx addr_ctx,
                      SshIpAddr ip,
                      SshIPDeviceCompletionCB callback,
                      void *context);

/*--------------------------------------------------------------------------
  Adds the specified IP address (alias) to the interface specified by 
  'adapter'. Returns 'context' of the created address in 'ctx_return'.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_add_address(SshIPDevice device,
                      SshAdapter adapter,
                      SshIpAddr ip,
                      SshAddressCtx *ctx_return,
                      SshIPDeviceCompletionCB callback,
                      void *context);

/*--------------------------------------------------------------------------
  Deletes the IP address (alias) specified by the 'address context' 
  previously returned by ssh_ipdev_add_address().
  --------------------------------------------------------------------------*/
void
ssh_ipdev_delete_address(SshIPDevice device,
                         SshAddressCtx addr_ctx,
                         SshIPDeviceCompletionCB callback,
                         void *context);

/*--------------------------------------------------------------------------
  Adds the specified route into the routing table.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_add_route(SshIPDevice device,
                    SshIPRoute route,
                    SshIPDeviceCompletionCB callback,
                    void *context);

/*--------------------------------------------------------------------------
  Removes the specified route from the routing table.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_remove_route(SshIPDevice device,
                       SshIPRoute route,
                       SshIPDeviceCompletionCB callback,
                       void *context);

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  Interface number lookup function that has to be implemented in the 
  interceptor specific code.
  --------------------------------------------------------------------------*/
SshInterceptorIfnum
ssh_adapter_ifnum_lookup(SshInterceptor interceptor,
                         unsigned char *mac_address,
                         size_t mac_address_len,
                         SshIPInterfaceID id);

#ifdef __cplusplus
}
#endif

#endif /* SSH_IPDEVICE_H */

