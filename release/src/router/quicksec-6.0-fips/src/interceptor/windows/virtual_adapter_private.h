/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Virtual adapter declarations internal to the interceptor
*/

#ifndef _VIRTUAL_ADAPTER_PRIVATE_H
#define _VIRTUAL_ADAPTER_PRIVATE_H

#include "sshincludes.h"

#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter.h"
#include "interceptor_i.h"
#include "sshvnic.h"

/* Flags for ssh_virtual_adapter_find() */ 
#define SSH_VA_ACTIVE     0x00000001 
#define SSH_VA_INACTIVE   0x00000002

#define SSH_VIRTUAL_ADAPTER_MAX_ADDRESSES 4

/* Flags for the virtual adapter. */
#define SSH_VIRTUAL_ADAPTER_FLAG_DEREGISTER 0x0001

/* IP address configuration context. */
typedef struct SshVirtualAdapterAddressRec
{
  SshIpAddrStruct ip;
  SshAddressCtx id;
  SshUInt32 active;
} SshVirtualAdapterAddressStruct, *SshVirtualAdapterAddress;

/* Context structure for a virtual adapter. */
typedef struct SshVirtualAdapterRec 
{
  /* Interceptor context */ 
  SshInterceptor interceptor;

  /* Reference count for this adapter object */
  LONG ref_count;

  SshKernelMutexStruct connect_lock;
  Boolean va_connected;
  Boolean va_connect_aborted;

  /* Back pointer to corresponding NDIS adapter object maintained 
     by the interceptor. */ 
  SshAdapter adapter;   

  /* Own, private interface */
  SshIceptDrvIfStruct own_if;

  /* The private interface of the underlying virtual NIC */ 
  unsigned short               vnic_if_version;   
  void *                       vnic_cb_context; 
  union
  {
    SshInterceptorConnectCB    vnic_connect_cb_v1;
    SshInterceptorConnectV2CB  vnic_connect_cb_v2;
  };
  SshInterceptorDisconnectCB   vnic_disconnect_cb;   
  SshVnicEnableCB              vnic_enable_cb;      
  SshVnicDisableCB             vnic_disable_cb; 
  SshVnicConfigureCB           vnic_configure_cb;
  SshVnicIndicateReceiveCB     vnic_receive_cb;

  /* Pointer to the file object corresponding to the device object of
     the underlying virtual NIC */
  void *file_object;
   
  /* Name of the virtual adapter. */ 
  char adapter_name[32];

  /* Engine callbacks */
  SshVirtualAdapterPacketCB packet_cb;
  SshVirtualAdapterDetachCB detach_cb;

  /* Adapter context supplied by engine */
  void *adapter_context;

  /* Adapter state configured by engine */
  SshVirtualAdapterState adapter_state;

  /* Configured IP addresses */
  SshVirtualAdapterAddressStruct addresses[SSH_VIRTUAL_ADAPTER_MAX_ADDRESSES];
  SshUInt32 num_addresses;
  SshUInt32 num_addresses_active;

  /* Address activation/deactivation callback */
  void (__fastcall *address_callback)(Boolean, void *);
  void *address_context;
  
  SshUInt32 flags;
} SshVirtualAdapterStruct, *SshVirtualAdapter;


/* "Allocates" a new virtual adapter */ 
SshVirtualAdapter 
ssh_virtual_adapter_alloc(SshInterceptor interceptor);

/* "Frees" a previously allocated virtual adapter */ 
void 
ssh_virtual_adapter_free(SshVirtualAdapter va);

/* "Frees" all previously allocated virtual adapters */ 
void 
ssh_virtual_adapter_free_all(SshInterceptor interceptor);

/* Tells the virtual adapter that the specified addresses are now
   active in the protocol stack. */
void
ssh_virtual_adapter_report_addresses(SshVirtualAdapter va,
                                     SshInterfaceAddress addrs,
                                     SshUInt32 num_addrs);

/* Checks whether the 'private_interface' structure, received as a
   response to OID_SSH_QUERY_INTERFACE request, is a supported virtual
   adapter interface. */
Boolean
ssh_is_virtual_adapter_interface(void *private_interface,
                                 SshUInt32 interface_size);

/* "Registers" new adapter as a virtual adapter. */
SshVirtualAdapter
ssh_virtual_adapter_register(SshInterceptor interceptor,
                             SshAdapter adapter,
                             void *private_interface,
                             SshUInt32 interface_size);

/* "Deregisters" an existing virtual adapter. */
void
ssh_virtual_adapter_deregister(SshVirtualAdapter va);

/* Increases the reference count of a virtual adapter. */
void
ssh_virtual_adapter_add_ref(IN SshVirtualAdapter va);

/* Decreases the reference count of a virtual adapter and destroys it if
 * reference count reaches zero. */
void
ssh_virtual_adapter_release(SshVirtualAdapter va);

#endif /* SSH_BUILD_IPSEC */
#endif /* _VIRTUAL_ADAPTER_PRIVATE_H */ 
