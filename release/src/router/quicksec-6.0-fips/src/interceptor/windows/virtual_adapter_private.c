/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of private functions for virtual adapter
   on Windows platforms
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#include "sshencode.h"
#include "kernel_timeouts.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorVirtualAdapterPrivate"

#define SSH_IS_VALID_CODE_PTR(ptr)  (ptr != NULL_FNPTR)

#define ssh_reference_object(obj)    \
do                                   \
{                                    \
  SSH_ASSERT((obj) != NULL);         \
  ObReferenceObject((obj));          \
} while (0);

#define ssh_dereference_object(obj)  \
do                                   \
{                                    \
  SSH_ASSERT((obj) != NULL);         \
  ObDereferenceObject((obj));        \
} while (0);

#pragma inline_depth(2)

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

static void
ssh_virtual_adapter_disconnect(SshVirtualAdapter va);

static void __fastcall
ssh_virtual_adapter_connect(SshVirtualAdapter va);

static SshInterceptorPacket
ssh_flat_packet_to_icept_packet(const SshInterceptor interceptor,
                                const SshAdapter adapter,
                                unsigned char * flat_packet,
                                unsigned int flat_packet_size);

/*--------------------------------------------------------------------------
  CALLBACK FUNCTIONS USED BY VNIC
  --------------------------------------------------------------------------*/

/* ssh_virtual_adapter_add_ref()
 *
 * Increase the reference count of a virtual adapter.
 */
void
ssh_virtual_adapter_add_ref(SshVirtualAdapter va)
{
  LONG new_value;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_virtual_adapter_add_ref(0x%p)", va));

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->interceptor != NULL);

  new_value = InterlockedIncrement(&va->ref_count);
  SSH_ASSERT(new_value > 1);
}


/* ssh_virtual_adapter_release()
 *
 * Decrease the reference count of a virtual adapter and destroy it if
 * reference count reaches zero.
 */
void
ssh_virtual_adapter_release(SshVirtualAdapter va)
{
  LONG ref_count;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_virtual_adapter_release(0x%p)", va));

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->interceptor != NULL);

  ref_count = InterlockedDecrement(&va->ref_count);
  SSH_ASSERT(ref_count >= 0);

  if (ref_count > 0)
    return;

  SSH_ASSERT(va->file_object == NULL);

  /* Make the engine detach this virtual adapter. */

  detach_cb = va->detach_cb;
  adapter_context = va->adapter_context;

  va->detach_cb = NULL;
  va->adapter_context = NULL;

  if (detach_cb)
    (*detach_cb)(adapter_context);

  /* And free. */

  NdisZeroMemory(va, sizeof(*va));
  ssh_free(va);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual NIC destroyed"));
}


/* ssh_virtual_adapter_send_cb()
 *
 * Underlying virtual NIC sends a packet to the engine.
 */
NDIS_STATUS
ssh_virtual_adapter_send_cb(SshVirtualAdapter va,
			    unsigned char *flat_packet,
			    unsigned int flat_packet_len)
{
  SshInterceptorPacket pp;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  /* We assume that that engine doesn't actually need the adapter ID and thus
     we just pick the first virtual adapter in vnic's list. (If we have only
     one virtual adapter, this is the correct one, of course). */

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->interceptor != NULL);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("ssh_virtual_adapter_send_cb(%s, len=%d)",
	     va->adapter_name, flat_packet_len));

  if (va->packet_cb)
    {
      SSH_IRQL old_irql;

      SSH_ASSERT(va->adapter != NULL);

      SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);

      /* Forward the packet to engine */
      pp = ssh_flat_packet_to_icept_packet(va->interceptor,
                                           va->adapter,
                                           flat_packet, flat_packet_len);

      if (pp)
        {
          (*va->packet_cb)(va->interceptor, pp, va->adapter_context);
        }

      SSH_LOWER_IRQL(old_irql);
    }
  else
    {
      status = NDIS_STATUS_FAILURE;
    }

  return status;
}


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------*/
/* ssh_is_ssh_virtual_nic()
 *
 * Function returns TRUE, if 'vnic_if' can be identified as an interface to
 * INSIDE Secure virtual NIC.
 *
 */
Boolean
ssh_is_ssh_virtual_nic(const SshVnicDrvIf vnic_if)
{
  Boolean is_vnic = FALSE;

  if (vnic_if->signature != SSH_ICEPT_VNIC_SIGNATURE)
    return FALSE;

  if ((vnic_if->version == SSH_ICEPT_VNIC_IF_VERSION_1)
      && (vnic_if->size != sizeof(SshVnicDrvIfStruct_V1)))
    return FALSE;

  if ((vnic_if->version == SSH_ICEPT_VNIC_IF_VERSION_2)
      && (vnic_if->size != sizeof(SshVnicDrvIfStruct_V2)))
    return FALSE;

  if (SSH_IS_VALID_CODE_PTR(vnic_if->configure_cb) &&
      SSH_IS_VALID_CODE_PTR(vnic_if->connect_cb) &&
      SSH_IS_VALID_CODE_PTR(vnic_if->disable_cb) &&
      SSH_IS_VALID_CODE_PTR(vnic_if->disconnect_cb) &&
      SSH_IS_VALID_CODE_PTR(vnic_if->enable_cb) &&
      SSH_IS_VALID_CODE_PTR(vnic_if->receive_cb))
    {
      is_vnic = TRUE;
    }

  return is_vnic;
}


/*--------------------------------------------------------------------------*/
/* ssh_virtual_adapter_device_add_ref()
 *
 * Increments the reference count of underlying virtual NIC's device object
 * thus ensuring that the virtual NIC can't be unloaded from memory.
 *
 * This function must be run on IRQL PASSIVE_LEVEL.
 *
 */
static Boolean
ssh_virtual_adapter_device_add_ref(SshVirtualAdapter va)
{
  Boolean status = TRUE;
  PDEVICE_OBJECT device_object = NULL;
  UNICODE_STRING device_name;

  SSH_DEBUG(SSH_D_MIDSTART, ("ssh_virtual_adapter_device_add_ref()"));

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->adapter != NULL);
  SSH_ASSERT(va->file_object == NULL);

  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  NdisInitUnicodeString(&device_name, NULL);

  if (ssh_adapter_device_object_name_get(va->adapter, &device_name))
    {
      SSH_ASSERT(device_name.Buffer != NULL);
      SSH_ASSERT(device_name.Length > 0);

      if (!NT_SUCCESS(IoGetDeviceObjectPointer(
				       &device_name, FILE_ALL_ACCESS,
				       (PFILE_OBJECT *)&va->file_object,
				       &device_object)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IoGetDeviceObjectPointer() FAILED!"));

          status = FALSE;
        }

      ssh_free(device_name.Buffer);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_device_object_name_get() FAILED!"));
      status = FALSE;
    }

  return (status);
}


/*--------------------------------------------------------------------------*/
/* ssh_virtual_adapter_device_release()
 *
 * Decrements the reference count of underlying virtual NIC device.
 *
 */
static void
ssh_virtual_adapter_device_release(SshVirtualAdapter va)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("ssh_virtual_adapter_device_release()"));

  SSH_ASSERT(va != NULL);

  ssh_dereference_object(va->file_object);
  va->file_object = NULL;
}


/* ssh_virtual_adapter_connect_retry_timeout_cb()
 *
 * This function gets never invoked on Win9x platforms
 */
static void
ssh_virtual_adapter_connect_retry_timeout_cb(SshVirtualAdapter va)
{
  Boolean aborted;
  SSH_DEBUG(SSH_D_MIDSTART,
	    ("ssh_virtual_adapter_connect_retry_timeout_cb()"));

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->interceptor != NULL);

  ssh_kernel_mutex_lock(&va->connect_lock);
  SSH_ASSERT(va->va_connected == 0);
  aborted = va->va_connect_aborted;
  ssh_kernel_mutex_unlock(&va->connect_lock);

  if (aborted)
    {
      SSH_DEBUG(SSH_D_MIDSTART,
                ("Virtual adapter connect aborted."));

      ssh_virtual_adapter_release(va);
    }
  else
    {
      /* force execution in passive level */
      ssh_ndis_wrkqueue_queue_item(va->interceptor->work_queue,
                                   ssh_virtual_adapter_connect, va);
    }
}


static void __fastcall
ssh_virtual_adapter_connect(SshVirtualAdapter va)
{
  SshVnicConnectIdStruct vnic_id;
  Boolean aborted = FALSE;

  SSH_DEBUG(SSH_D_MIDSTART, ("ssh_virtual_adapter_connect()"));

  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->interceptor != NULL);

  /* "Lock" the virtual NIC */
  if (ssh_virtual_adapter_device_add_ref(va))
    {

      switch (va->vnic_if_version)
        {
        case SSH_ICEPT_VNIC_IF_VERSION_1:
          SSH_ASSERT(va->vnic_connect_cb_v1 != NULL_FNPTR);
          SSH_ASSERT(va->vnic_cb_context != NULL);
          if (!(*va->vnic_connect_cb_v1)(va->vnic_cb_context, &va->own_if))
            {
              SSH_DEBUG(SSH_D_FAIL, ("VNIC connection FAILED!"));
              ssh_virtual_adapter_device_release(va);
            }
          break;

        case SSH_ICEPT_VNIC_IF_VERSION_2:
          vnic_id.type = VNIC_CONNECT_ID_MEDIA_ADDRESS;
          vnic_id.media_addr.addr = va->adapter->media_addr;
          vnic_id.media_addr.addr_len = va->adapter->media_addr_len;

          va->vnic_cb_context =
            (*va->vnic_connect_cb_v2)(&vnic_id, &va->own_if);
          if (va->vnic_cb_context == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("VNIC connection FAILED!"));
              ssh_virtual_adapter_device_release(va);
            }
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      ssh_kernel_mutex_lock(&va->connect_lock);
      if (va->va_connect_aborted == 1)
        aborted = TRUE;
      else
        va->va_connected = TRUE;
      ssh_kernel_mutex_unlock(&va->connect_lock);

      if (aborted)
        {
          if (va->vnic_cb_context)
            ssh_virtual_adapter_disconnect(va);
        }
      /* Release the connect ref */
      ssh_virtual_adapter_release(va);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Could not connect to VNIC!"));

      /* The underlying virtual NIC is not fully initialized yet, so let's try
         again after a while. We can't use this same function as a "timeout
         callback", because timeouts are executed at a raised IRQL on some
         Windows platforms (depends from interceptor's implementation) */
      ssh_kernel_mutex_lock(&va->connect_lock);
      if (va->va_connect_aborted == 1)
        aborted = TRUE;
      ssh_kernel_mutex_unlock(&va->connect_lock);

      /* Virtual adapter connect aborted. */
      if (aborted)
        {
          /* Release the connect ref */
          ssh_virtual_adapter_release(va);
          return;
        }

      ssh_kernel_timeout_register(1, 0,
			  ssh_virtual_adapter_connect_retry_timeout_cb,
			  va);
    }
}


static void
ssh_virtual_adapter_disconnect(SshVirtualAdapter va)
{
  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->vnic_disconnect_cb != NULL_FNPTR);

  /* disconnect from virtual NIC */
  (*va->vnic_disconnect_cb)(va->vnic_cb_context);

  /* decrement the reference count of vnic device */
  ssh_virtual_adapter_device_release(va);
}


/*--------------------------------------------------------------------------*/
/* ssh_is_virtual_adapter_interface()
 *
 * Return value:
 *
 *  TRUE if 'private_interface' is a valid virtual adapter interface
 *  FALSE 'private_interface' is not a virtual adapter interface
 */

Boolean
ssh_is_virtual_adapter_interface(void *private_interface,
                                 SshUInt32 interface_size)
{
  SshVnicDrvIf vnic_if = (SshVnicDrvIf)private_interface;
  SshUInt32 min_size;

  SSH_ASSERT(private_interface != NULL);

  /* Check whether the adapter really is SSH virtual NIC */
  min_size = MIN(sizeof(SshVnicDrvIfStruct_V1),
                 sizeof(SshVnicDrvIfStruct_V2));

  if ((interface_size >= min_size) && ssh_is_ssh_virtual_nic(vnic_if))
    return TRUE;
  else
    return FALSE;
}


/*--------------------------------------------------------------------------*/
/* ssh_virtual_adapter_register()
 *
 * Precondition:
 *
 * We have found an adapter that represent ssh virtual
 * adapter
 *
 * Postcondition:
 *
 * If return value is not NULL - virtual adapter record has
 * been allocated, record is associated with the adapter
 * record and also appended to the list of virtual adapters,
 * connection to vnic has been established.
 *
 * Initialized field is set to FALSE, because we are missing
 * the information passed by virtual_adapter_create() call.
 *
 * If return value is NULL - no additional memory allocated,
 * adapter structure untouched.
 *
 */

SshVirtualAdapter
ssh_virtual_adapter_register(SshInterceptor interceptor,
                             SshAdapter adapter,
                             void *private_interface,
                             SshUInt32 interface_size)
{
  SshVirtualAdapter va   = NULL;
  SshVnicDrvIf vnic_if   = (SshVnicDrvIf)private_interface;
  SshVnicDrvIf_V1 if_v1  = (SshVnicDrvIf_V1)vnic_if;
  SshVnicDrvIf_V2 if_v2  = (SshVnicDrvIf_V2)vnic_if;
  SshUInt32   dad_cnt    = 1;
  SshUInt32   link_local = 0;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("ssh_virtual_adapter_register, if_size=%d\n", interface_size));

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(private_interface != NULL);

  /* Check whether the adapter really is SSH virtual NIC */
  if (interface_size < sizeof(SshVnicDrvIfStruct) ||
      !ssh_is_ssh_virtual_nic(vnic_if))
    return NULL;

  /* allocate a new virtual adapter structure */
  if (!(va = ssh_calloc(1, sizeof *va)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed in "
			     "ssh_virtual_adapter_register()!"));
      return NULL;
    }

  va->interceptor = interceptor;
  va->ref_count = 1;
  va->adapter = adapter;

  ssh_kernel_mutex_init(&va->connect_lock);

  va->own_if.signature = SSH_ICEPT_VNIC_SIGNATURE;
  va->own_if.version   = SSH_ICEPT_VNIC_IF_VERSION;
  va->own_if.size = sizeof(SshIceptDrvIfStruct);
  va->own_if.cb_context = va;
  va->own_if.lock_cb = ssh_virtual_adapter_add_ref;
  va->own_if.release_cb = ssh_virtual_adapter_release;
  va->own_if.send_cb = ssh_virtual_adapter_send_cb;

  va->vnic_if_version = vnic_if->version;
  switch (va->vnic_if_version)
    {
    case SSH_ICEPT_VNIC_IF_VERSION_1:
      va->vnic_cb_context    = if_v1->cb_context;
      va->vnic_connect_cb_v1 = if_v1->connect_cb;
      va->vnic_disconnect_cb = if_v1->disconnect_cb;
      va->vnic_enable_cb     = if_v1->enable_cb;
      va->vnic_disable_cb    = if_v1->disable_cb;
      va->vnic_configure_cb  = if_v1->configure_cb;
      va->vnic_receive_cb    = if_v1->receive_cb;
      break;

    case SSH_ICEPT_VNIC_IF_VERSION_2:
      va->vnic_cb_context = NULL;
      va->vnic_connect_cb_v2 = if_v2->connect_cb;
      va->vnic_disconnect_cb = if_v2->disconnect_cb;
      va->vnic_enable_cb     = if_v2->enable_cb;
      va->vnic_disable_cb    = if_v2->disable_cb;
      va->vnic_configure_cb  = if_v2->configure_cb;
      va->vnic_receive_cb    = if_v2->receive_cb;
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_snprintf(va->adapter_name, sizeof va->adapter_name,
	       "%s", adapter->friendly_name);

  /* Connect to underlying NIC driver */
  /* Increase the ref_cnt, since we need it for va connect. We do
     not need to utilize Interlocked* for this yet, since it is not
     required at this stage. This refcount is held for the connect call
     & its timeouts etc... duration. */
  va->ref_count++;
  ssh_virtual_adapter_connect(va);

  /* Remove Duplicate address detection and link local
     addressing from this Virtual adapter.
     Do it for both IPv4 and IPv6 devices. */
  if (ssh_ipdev_is_connected(&interceptor->ip4_dev) &&
      ssh_ipdev_configure(&interceptor->ip4_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_DAD,
                          &dad_cnt) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Dad disable failed for IPv4 device"));
    }

  if (ssh_ipdev_is_connected(&interceptor->ip4_dev) &&
      ssh_ipdev_configure(&interceptor->ip4_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_IFACE_METRIC,
                          &dad_cnt) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Interface metric setting failed for"
                             " IPv4 device"));
    }

  if (ssh_ipdev_is_connected(&interceptor->ip4_dev) &&
      ssh_ipdev_configure(&interceptor->ip4_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_LINK_LOCAL,
                          &link_local) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Link local disable failed for IPv4 device"));
    }

#if defined(WITH_IPV6)
  if (ssh_ipdev_is_connected(&interceptor->ip6_dev) &&
      ssh_ipdev_configure(&interceptor->ip6_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_DAD,
                          &dad_cnt) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Dad disable failed for IPv6 device"));
    }

  if (ssh_ipdev_is_connected(&interceptor->ip6_dev) &&
      ssh_ipdev_configure(&interceptor->ip6_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_IFACE_METRIC,
                          &dad_cnt) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Interface metric setting failed for"
                             " IPv6 device"));
    }

  if (ssh_ipdev_is_connected(&interceptor->ip6_dev) &&
      ssh_ipdev_configure(&interceptor->ip6_dev, adapter,
                          SSH_IPDEV_CONFIGURE_TYPE_LINK_LOCAL,
                          &link_local) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Link local disable failed for IPv6 device"));
    }
#endif /* WITH_IPV6 */

  /* Increment the va_interface_cnt. This is useful e.g. in the
     policymanager shutdown case. */
  InterlockedIncrement(&interceptor->va_interface_cnt);
  return va;
}

/*---------------------------------------------------------------------------*/
/* ssh_virtual_adapter_deregister()
 *
 *
 *
 */
void
ssh_virtual_adapter_deregister(SshVirtualAdapter va)
{
  SshInterceptor interceptor = va->interceptor;
  Boolean was_connected = FALSE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("ssh_virtual_adapter_deregister(0x%p)", va));

  ssh_kernel_mutex_lock(&va->connect_lock);
  was_connected = va->va_connected;
  va->va_connect_aborted = TRUE;
  ssh_kernel_mutex_unlock(&va->connect_lock);

  SSH_ASSERT(va->interceptor != NULL);
  SSH_ASSERT(va != NULL);
  SSH_ASSERT(va->adapter != NULL);

  if (was_connected)
    {
      SSH_ASSERT(va->vnic_disable_cb != NULL_FNPTR);
      SSH_ASSERT(va->vnic_cb_context != NULL);

      /* disable adapter - this 'unplugs the cable' */
      (*va->vnic_disable_cb)(va->vnic_cb_context);

      /* Disconnect from underlying virtual NIC */
      ssh_virtual_adapter_disconnect(va);
    }

  /* Decrement the count of virtual adapters */
  InterlockedDecrement(&interceptor->va_interface_cnt);

  /* release the virtual adapter. */
  ssh_virtual_adapter_release(va);
}

/*--------------------------------------------------------------------------*/
void
ssh_virtual_adapter_report_addresses(SshVirtualAdapter va,
                                     SshInterfaceAddress addrs,
                                     SshUInt32 num_addrs)
{
  SshVirtualAdapterAddress vaa;
  SshInterfaceAddress ia;
  SshUInt32 i, j;

  for (i = 0; i < SSH_VIRTUAL_ADAPTER_MAX_ADDRESSES; i++)
    {
      vaa = &va->addresses[i];

      if (SSH_IP_IS_NULLADDR(&vaa->ip))
        continue;

      for (j = 0; j < num_addrs; j++)
        {
          ia = &addrs[j];
          if ((ia->protocol == SSH_PROTOCOL_IP4 ||
               ia->protocol == SSH_PROTOCOL_IP6) &&
              SSH_IP_EQUAL(&ia->addr.ip.ip, &vaa->ip))
            break;
        }

      if (j < num_addrs)
        {
          if (!vaa->active)
            {
              SSH_DEBUG(SSH_D_MIDSTART, ("Address %@ of virtual adapter %s "
                                         "became active", ssh_ipaddr_render,
                                         &vaa->ip, va->adapter_name));
              vaa->active = 1;
              va->num_addresses_active++;
            }
        }
    }

  if (va->address_callback)
    (*va->address_callback)(TRUE, va->address_context);
}


/*--------------------------------------------------------------------------*/
SshInterceptorPacket
ssh_flat_packet_to_icept_packet(const SshInterceptor interceptor,
                                const SshAdapter adapter,
                                unsigned char * flat_packet,
                                unsigned int flat_packet_size)
{
  SshInterceptorPacket pp;

  pp = ssh_interceptor_packet_alloc(interceptor, SSH_PACKET_FROMPROTOCOL,
                                    SSH_PROTOCOL_ETHERNET, adapter->ifnum,
				    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    flat_packet_size);
  if (pp)
    {
      if (!ssh_interceptor_packet_copyin(pp, 0, flat_packet,
                                         flat_packet_size))
        {
          ssh_interceptor_packet_free(pp);
          pp = NULL;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Can not allocate new packet"));
    }

  return pp;
}

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
