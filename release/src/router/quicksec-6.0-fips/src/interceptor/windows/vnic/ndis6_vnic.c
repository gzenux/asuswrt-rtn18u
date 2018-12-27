/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VNIC, virtual network interface for implementing virtual-IP feature
   on Windows platforms.

   Virtual NIC is implemented as a NDIS 6.0 miniport driver
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/

#include <stddef.h>
#include <ndis.h>
#include "sshvnic.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* This definition limits the amount of virtual NIC instances can be created.
   You may increase this value when necessary. Note, however, that "too many"
   virtual adapters could cause us to run out of NonPagedPool if the packet
   interceptor is allocating packet pools per adapter basis. */
#define SSH_MAX_VNIC_INSTANCES        10

#if defined(NDIS60_MINIPORT)
#ifdef NDIS_SUPPORT_NDIS630
#define SSH_VNIC_NDIS_MAJOR_VERSION   6
#define SSH_VNIC_NDIS_MINOR_VERSION   30
#elif NDIS_SUPPORT_NDIS620
#define SSH_VNIC_NDIS_MAJOR_VERSION   6
#define SSH_VNIC_NDIS_MINOR_VERSION   20
#elif NDIS_SUPPORT_NDIS61
#define SSH_VNIC_NDIS_MAJOR_VERSION   6
#define SSH_VNIC_NDIS_MINOR_VERSION   1
#else
#define SSH_VNIC_NDIS_MAJOR_VERSION   6
#define SSH_VNIC_NDIS_MINOR_VERSION   0
#endif
#else
#error "Legacy NDIS versions not supported!"
#endif

#define SSH_DRIVER_MAJOR_VERSION      5
#define SSH_DRIVER_MINOR_VERSION      2

#define SSH_ETHERNET_HEADER_SIZE      14
#define SSH_DEFAULT_MTU               1400
#define SSH_MAXIMUM_PACKET_SIZE  \
  (SSH_ETHERNET_HEADER_SIZE + SSH_DEFAULT_MTU)

#define SSH_VNIC_MEDIUM               NdisMedium802_3
#define SSH_VNIC_INITIAL_MEDIA_STATE  MediaConnectStateDisconnected

#define SSH_VNIC_LINK_SPEED           1000000000
#define SSH_VNIC_BUFFER_SPACE         SSH_MAXIMUM_PACKET_SIZE
#define SSH_VENDOR_DRIVER_VERSION  \
  ((SSH_DRIVER_MAJOR_VERSION << 16) | SSH_DRIVER_MINOR_VERSION)

#define SSH_VNIC_MAC_OPTIONS          (NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | \
                                       NDIS_MAC_OPTION_TRANSFERS_NOT_PEND)

#define SSH_VNIC_SUPPORTED_STATISTICS  \
                        (NDIS_STATISTICS_XMIT_OK_SUPPORTED | \
                         NDIS_STATISTICS_RCV_OK_SUPPORTED | \
                         NDIS_STATISTICS_XMIT_ERROR_SUPPORTED | \
                         NDIS_STATISTICS_RCV_ERROR_SUPPORTED | \
                         NDIS_STATISTICS_RCV_NO_BUFFER_SUPPORTED | \
                         NDIS_STATISTICS_TRANSMIT_QUEUE_LENGTH_SUPPORTED | \
                         NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED)

#define SSH_VNIC_SUPPORTED_PACKET_FILTERS \
                        (NDIS_PACKET_TYPE_DIRECTED | \
                         NDIS_PACKET_TYPE_MULTICAST | \
                         NDIS_PACKET_TYPE_ALL_MULTICAST | \
                         NDIS_PACKET_TYPE_BROADCAST)

/* MAXIMUM_SEND_PACKETS should be one, if we only have MiniportSend */
#define SSH_VNIC_MAXIMUM_SEND_PACKETS     1
#define SSH_VNIC_MAX_MULTICAST_ADDRESSES  32

#define SSH_MEM_BLOCK_HAS_BEEN_FREED 0xFFFFFFFF

#define SSH_VNIC_IS_ENABLED(vnic) \
  ((vnic->connect_status == NdisMediaStateConnected) ? TRUE : FALSE)

#pragma inline_depth(2)


/* Data structures */

typedef UCHAR EthernetAddress[ETH_LENGTH_OF_ADDRESS];

typedef enum
{
  SSH_VNIC_STATE_HALTED,
  SSH_VNIC_STATE_INITIALIZING,
  SSH_VNIC_STATE_PAUSED,
  SSH_VNIC_STATE_RESTARTING,
  SSH_VNIC_STATE_RUNNING,
  SSH_VNIC_STATE_PAUSING,
  SSH_VNIC_STATE_SHUTDOWN
} SshVnicState;

typedef struct SshVnicRec
{
  /* A handle identifying the miniport's NIC.
     The value is assigned by the NDIS library and passed
     as parameter to MiniportInitialize(Ex) */
  NDIS_HANDLE miniport_handle;

  /* Adapter state as specified in DDK */
  LONG state;

  /* Number of send/receive operations currently pending */
  LONG pending_operations;

  /* Connect status of the vnic.
     Connect status is initially set to SSH_VNIC_INITIAL_MEDIA_STATE,
     and is switched by the interceptor by call of ssh_vnic_enable()
     and ssh_vnic_disable() */
  NDIS_MEDIA_STATE connect_status;

  /* virtual ethernet addresses */
  EthernetAddress mac_address;
  EthernetAddress multicast_addresses[SSH_VNIC_MAX_MULTICAST_ADDRESSES];
  UINT nbr_of_mc_addresses;

  /* data set by the stack */
  ULONG packet_filter; /* the current packet filter in use */
  ULONG lookahead_size; /* size of the lookahead buffer */
  ULONG protocol_options; /* current protocol options */

  /* data locks */
  NDIS_SPIN_LOCK lock; /* spinlock protecting this structure */
  NDIS_SPIN_LOCK icept_if_lock; /* spinlock protecting icept_if */

  /* statistics counters - retrieved by the protocol */
  unsigned __int64 good_transmits;
  unsigned __int64 good_receives;
  unsigned __int64 bad_transmits;
  unsigned __int64 bad_receives;
  unsigned __int64 bad_receives_no_buffer;

  /* exported interface */
  SshVnicDrvIfStruct_V1 own_if;

  /* imported interceptor interface */
  SshIceptDrvIf icept_if;
  BOOLEAN locking_in_progress; /* see ssh_vnic_icept_if_get() */
  BOOLEAN initialized;
} SshVnicStruct, *SshVnic;


/* Data structure to be used as a context for a "MiniportTransferData" */
typedef struct SshTransferDataContextRec
{
  /* Transfer data buffer. Contains the _data_ portion of the packet
     we're sending.  */
  unsigned char * data;
  unsigned int data_len;
} SshTransferDataContextStruct, * SshTransferDataContext;


typedef struct SshVnicIoDeviceRec
{
  /* Pointer to the NT device object */
  PDEVICE_OBJECT device;
} SshVnicIoDeviceStruct, *SshVnicIoDevice;


/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/* this enumerates current vnics. id is used as part of mac
   address of the adapter */
static ULONG global_vnic_id = 0;
static ULONG vnic_instances = 0;
static SshVnicStruct vnic_table[SSH_MAX_VNIC_INSTANCES];

static SshVnicDrvIfStruct own_if;

/*-------------------------------------------------------------------------
  CONSTANTS
  -------------------------------------------------------------------------*/

static NDIS_GUID
ssh_vnic_supported_guids[] =
{ {0x7c4311b7,0x9a5d,0x4a31, {0xb0,0x9d,0x7e,0xf3,0x0,0xf8,0x24,0x4d}},
  OID_SSH_QUERY_INTERFACE,
  sizeof(SshVnicDrvIfStruct),
  fNDIS_GUID_TO_OID | fNDIS_GUID_ALLOW_READ};

static NDIS_OID
ssh_vnic_supported_oids[] =
{



  /*
     List of OIDs we support
     NOTE! This list should be in ascending order by OID value.
     (Otherwise NDIS calls behave rather oddly)
  */
  /* General Operational Characteristics Objects */
  OID_GEN_SUPPORTED_LIST,
  OID_GEN_HARDWARE_STATUS,
  OID_GEN_MEDIA_SUPPORTED,
  OID_GEN_MEDIA_IN_USE,
  OID_GEN_MAXIMUM_LOOKAHEAD,
  OID_GEN_MAXIMUM_FRAME_SIZE,
  OID_GEN_LINK_SPEED,
  OID_GEN_TRANSMIT_BUFFER_SPACE,
  OID_GEN_RECEIVE_BUFFER_SPACE,
  OID_GEN_TRANSMIT_BLOCK_SIZE,
  OID_GEN_RECEIVE_BLOCK_SIZE,
  OID_GEN_VENDOR_ID,
  OID_GEN_VENDOR_DESCRIPTION,
  OID_GEN_VENDOR_DRIVER_VERSION,
  OID_GEN_CURRENT_PACKET_FILTER,
  OID_GEN_CURRENT_LOOKAHEAD,
  OID_GEN_DRIVER_VERSION,
  OID_GEN_MAXIMUM_TOTAL_SIZE,
  OID_GEN_PROTOCOL_OPTIONS,
  OID_GEN_MAC_OPTIONS,
  OID_GEN_MEDIA_CONNECT_STATUS,
  OID_GEN_MAXIMUM_SEND_PACKETS,
  OID_GEN_NETWORK_LAYER_ADDRESSES,
  OID_GEN_TRANSPORT_HEADER_OFFSET,
  OID_GEN_TRANSMIT_QUEUE_LENGTH,
  OID_GEN_PHYSICAL_MEDIUM,

  /* General Statistics Objects */
  OID_GEN_XMIT_OK,
  OID_GEN_RCV_OK,
  OID_GEN_XMIT_ERROR,
  OID_GEN_RCV_ERROR,
  OID_GEN_RCV_NO_BUFFER,
  OID_GEN_STATISTICS,

  /* Ethernet Objects */
  OID_802_3_PERMANENT_ADDRESS,
  OID_802_3_CURRENT_ADDRESS,
  OID_802_3_MULTICAST_LIST,
  OID_802_3_MAXIMUM_LIST_SIZE,
  OID_802_3_MAC_OPTIONS,
  OID_802_3_RCV_ERROR_ALIGNMENT,
  OID_802_3_XMIT_ONE_COLLISION,
  OID_802_3_XMIT_MORE_COLLISIONS,
  /* Plug-and-Play and Power-Management Objects */

  /* Task Offload Objects */
  OID_TCP_TASK_OFFLOAD,

  OID_GEN_SUPPORTED_GUIDS,

  /* Custom OID's */
  OID_SSH_QUERY_INTERFACE
};


static const unsigned char
vendor_description[] = "INSIDE Secure QuickSec Virtual Adapter";

static const NDIS_PNP_CAPABILITIES
ssh_vnic_pnp_capabilities =
{
  NDIS_DEVICE_WAKE_UP_ENABLE,
  {NdisDeviceStateUnspecified,
   NdisDeviceStateUnspecified,
   NdisDeviceStateUnspecified}
};

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

/*---------- MINIPORT INTERFACE ----------*/
/* "MiniportInitialize" */
static NDIS_STATUS
ssh_vnic_initialize(NDIS_HANDLE miniport_handle,
                    NDIS_HANDLE driver_context,
                    PNDIS_MINIPORT_INIT_PARAMETERS init_params);

/* "MiniportSetOptions" */
static NDIS_STATUS
ssh_vnic_set_options(NDIS_HANDLE miniport_handle,
                     NDIS_HANDLE driver_context);

/* "MiniportPause" */
static NDIS_STATUS
ssh_vnic_pause(NDIS_HANDLE adapter_context,
               PNDIS_MINIPORT_PAUSE_PARAMETERS params);

/* "MiniportRestart" */
static NDIS_STATUS
ssh_vnic_restart(NDIS_HANDLE adapter_context,
                 PNDIS_MINIPORT_RESTART_PARAMETERS params);

/* "MiniportOidRequest" */
static NDIS_STATUS
ssh_vnic_oid_request(NDIS_HANDLE adapter_context,
                     PNDIS_OID_REQUEST oid_request);

/* "MiniportCancelOidRequest" */
static VOID
ssh_vnic_cancel_oid_request(NDIS_HANDLE adapter_context,
                            PVOID request_id);

/* "MiniportSendNetBufferLists" */
static VOID
ssh_vnic_send(NDIS_HANDLE adapter_context,
              PNET_BUFFER_LIST net_buffer_lists,
              NDIS_PORT_NUMBER port_number,
              ULONG send_flags);

/* "MiniportCancelSend" */
static VOID
ssh_vnic_cancel_send(NDIS_HANDLE adapter_context,
                     PVOID cancel_id);

/* "MiniportReturnNetBufferLists" */
static VOID
ssh_vnic_return_nbls(NDIS_HANDLE adapter_context,
                     PNET_BUFFER_LIST net_buffer_lists,
                     ULONG return_flags);

/* "MiniportCheckForHangEx" */
static BOOLEAN
ssh_vnic_check_for_hang(NDIS_HANDLE adapter_context);

/* "MiniportReset" */
static NDIS_STATUS
ssh_vnic_reset(NDIS_HANDLE adapter_context,
               PBOOLEAN addressing_reset);

/* "MiniportDevicePnPEventNotify" */
static VOID
ssh_vnic_pnp_event_notify(NDIS_HANDLE adapter_context,
                          PNET_DEVICE_PNP_EVENT pnp_event);

/* "MiniportHaltEx" */
static VOID
ssh_vnic_halt(NDIS_HANDLE adapter_context,
              NDIS_HALT_ACTION action);

/* "MiniportShutdownEx" */
static VOID
ssh_vnic_shutdown(NDIS_HANDLE adapter_context,
                  NDIS_SHUTDOWN_ACTION action);

/* "MiniportDriverUnload" */
static VOID
ssh_vnic_unload(PDRIVER_OBJECT driver_object);

DRIVER_DISPATCH ssh_vnic_dispatch;

/*---------- Private interface for SSH Packet Interceptor ----------*/
static BOOLEAN
ssh_vnic_icept_connect(SshVnic vnic,
                       SshIceptDrvIf icept_if);

static void *
ssh_vnic_icept_connect_v2(void *vnic_id,
                          SshIceptDrvIf icept_if);

static void
ssh_vnic_icept_disconnect(SshVnic vnic);

static BOOLEAN
ssh_vnic_enable(SshVnic vnic);

static void
ssh_vnic_disable(SshVnic vnic);

static BOOLEAN
ssh_vnic_configure(SshVnic vnic,
                   UINT type,
                   void * data);

static void
ssh_vnic_receive(SshVnic vnic,
                 unsigned char * buffer,
                 unsigned int buffer_len);

/*---------- Local Functions ----------*/

NDIS_STATUS
DriverEntry(PVOID argument1,
            PVOID argument2);

static NDIS_STATUS __fastcall
ssh_vnic_switch_connect_status(SshVnic vnic,
                               NDIS_MEDIA_STATE new_state);

static SshIceptDrvIf __fastcall
ssh_vnic_interceptor_if_get(SshVnic vnic,
                            BOOLEAN remove);

static void *
ssh_vnic_alloc(ULONG size);

static void
ssh_vnic_free(void * ptr);



static NDIS_HANDLE    vnic_driver_handle = NULL;
static PDEVICE_OBJECT vnic_device_object = NULL;
static NDIS_HANDLE    vnic_device_handle = NULL;

#pragma NDIS_INIT_FUNCTION(DriverEntry)

/*-------------------------------------------------------------------------
  DriverEntry()
  -------------------------------------------------------------------------*/
NDIS_STATUS
DriverEntry(PDRIVER_OBJECT driver_object,
            PVOID registry_path)
{
  NDIS_MINIPORT_DRIVER_CHARACTERISTICS mchars;
  NDIS_STATUS status;

  /* Initialize our own private interface structure, which will be
     exposed to the interceptor */
  own_if.signature = SSH_ICEPT_VNIC_SIGNATURE;
  own_if.version   = SSH_ICEPT_VNIC_IF_VERSION;
  own_if.size = sizeof(SshVnicDrvIfStruct);
  own_if.connect_cb = ssh_vnic_icept_connect_v2;
  own_if.disconnect_cb = ssh_vnic_icept_disconnect;
  own_if.enable_cb = ssh_vnic_enable;
  own_if.disable_cb = ssh_vnic_disable;
  own_if.configure_cb = ssh_vnic_configure;
  own_if.receive_cb = ssh_vnic_receive;

  NdisZeroMemory(&mchars, sizeof(mchars));

#ifdef NDIS_SUPPORT_NDIS61
  mchars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
  mchars.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
  mchars.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
#else
  mchars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
  mchars.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
  mchars.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
#endif

  mchars.MajorNdisVersion = SSH_VNIC_NDIS_MAJOR_VERSION;
  mchars.MinorNdisVersion = SSH_VNIC_NDIS_MINOR_VERSION;
  mchars.MajorDriverVersion = SSH_DRIVER_MAJOR_VERSION;
  mchars.MinorDriverVersion = SSH_DRIVER_MINOR_VERSION;

  mchars.Flags = 0;

  mchars.SetOptionsHandler = ssh_vnic_set_options;
  mchars.InitializeHandlerEx = ssh_vnic_initialize;
  mchars.HaltHandlerEx = ssh_vnic_halt;
  mchars.UnloadHandler = ssh_vnic_unload;
  mchars.PauseHandler = ssh_vnic_pause;
  mchars.RestartHandler = ssh_vnic_restart;
  mchars.OidRequestHandler = ssh_vnic_oid_request;
  mchars.CancelOidRequestHandler = ssh_vnic_cancel_oid_request;
  mchars.SendNetBufferListsHandler = ssh_vnic_send;
  mchars.CancelSendHandler = ssh_vnic_cancel_send;
  mchars.ReturnNetBufferListsHandler = ssh_vnic_return_nbls;
  mchars.CheckForHangHandlerEx = ssh_vnic_check_for_hang;
  mchars.ResetHandlerEx = ssh_vnic_reset;
  mchars.DevicePnPEventNotifyHandler = ssh_vnic_pnp_event_notify;
  mchars.ShutdownHandlerEx = ssh_vnic_shutdown;

  do {
    status = NdisMRegisterMiniportDriver(driver_object,
                                        registry_path,
                                        (PNDIS_HANDLE)NULL,
                                        &mchars,
                                        &vnic_driver_handle);

    if (status != NDIS_STATUS_SUCCESS)
      {
        /* ssh_vnic_unload(driver_object); */
        status = NDIS_STATUS_FAILURE;
        break;
      }

    if (status == NDIS_STATUS_SUCCESS)
      {
        NDIS_DEVICE_OBJECT_ATTRIBUTES obj_attrs;
        PDRIVER_DISPATCH fn_table[IRP_MJ_MAXIMUM_FUNCTION + 1];
        NDIS_STATUS ndis_st;
        UNICODE_STRING dev_name;
        UNICODE_STRING empty_link;
        UNICODE_STRING ddl_string;

        NdisZeroMemory(fn_table, sizeof(fn_table));
        fn_table[IRP_MJ_CREATE] = ssh_vnic_dispatch;
        fn_table[IRP_MJ_CLEANUP] = ssh_vnic_dispatch;
        fn_table[IRP_MJ_CLOSE] = ssh_vnic_dispatch;
        fn_table[IRP_MJ_INTERNAL_DEVICE_CONTROL] = ssh_vnic_dispatch;

        NdisInitUnicodeString(&dev_name, SSH_VNIC_IO_DEVICE_NAME);
        NdisInitUnicodeString(&empty_link, L"");
        NdisInitUnicodeString(&ddl_string, L"D:P"); /* Kernel only */

        NdisZeroMemory(&obj_attrs, sizeof(obj_attrs));
        obj_attrs.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
        obj_attrs.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
        obj_attrs.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
        obj_attrs.DeviceName = &dev_name;
        obj_attrs.SymbolicName = &empty_link; /* We don't need symbolic link */
        obj_attrs.MajorFunctions = fn_table;
        obj_attrs.ExtensionSize = 0;
        obj_attrs.DefaultSDDLString = &ddl_string;
        obj_attrs.DeviceClassGuid = NULL;

        ndis_st = NdisRegisterDeviceEx(vnic_driver_handle,
          &obj_attrs,
          &vnic_device_object,
          &vnic_device_handle);
      }
  } while (0);

  return status;
}


/*---------- NDIS Miniport Interface ----------*/

/*-------------------------------------------------------------------------
  ssh_vnic_set_options()
  -------------------------------------------------------------------------*/
#pragma NDIS_PAGEABLE_FUNCTION(ssh_vnic_set_options)

static NDIS_STATUS
ssh_vnic_set_options(NDIS_HANDLE miniport_handle,
                     NDIS_HANDLE driver_context)
{
  PAGED_CODE();

  /* Nothing to do.  */
  return NDIS_STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------
  ssh_vnic_initialize()
  -------------------------------------------------------------------------*/
#pragma NDIS_PAGEABLE_FUNCTION(ssh_vnic_initialize)

static NDIS_STATUS
ssh_vnic_initialize(NDIS_HANDLE adapter_handle,
                    NDIS_HANDLE driver_context,
                    PNDIS_MINIPORT_INIT_PARAMETERS init_params)
{
  NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES reg_attrs;
  NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen_attrs;
  NDIS_STATUS status;
  ULONG i;
  ULONG vnic_id;
  ULONG vnic_count;
  SshVnic vnic = NULL;

  PAGED_CODE();

  /* Check whether we already know this VNIC (this happens when we return back
     from low power state) */
  for (i = 0; i < SSH_MAX_VNIC_INSTANCES; i++)
    {
      if ((vnic_table[i].initialized == TRUE)
          && (vnic_table[i].miniport_handle == adapter_handle))
        {
          vnic = &vnic_table[i];
          break;
        }
    }

  if (vnic == NULL)
    {
      /* Limit the amount of instances we create */
      vnic_count = InterlockedIncrement(&vnic_instances);
      if (vnic_count > SSH_MAX_VNIC_INSTANCES)
        {
          InterlockedDecrement(&vnic_instances);
          return NDIS_STATUS_FAILURE;
        }

      vnic_id = InterlockedIncrement(&global_vnic_id);
      vnic = &vnic_table[vnic_count - 1];

      NdisZeroMemory(vnic, sizeof(*vnic));
      vnic->miniport_handle = adapter_handle;
      vnic->connect_status = SSH_VNIC_INITIAL_MEDIA_STATE;
      /* Make "unique" MAC address. Generated ehthernet address has format
         02-00-00-00-XX-XX, where XX-XX is the global_adapter_id in native
         byte order */
      vnic->mac_address[0] = 2; /* set U/L bit up */
      NdisMoveMemory(&vnic->mac_address[4],
                     &((USHORT)vnic_id),
                     sizeof(USHORT));
      NdisAllocateSpinLock(&vnic->lock);
      NdisAllocateSpinLock(&vnic->icept_if_lock);
      /* Initialize our own private interface structure, which will be
         exposed to the interceptor */
      vnic->own_if.signature = SSH_ICEPT_VNIC_SIGNATURE;
      vnic->own_if.version   = SSH_ICEPT_VNIC_IF_VERSION;
      vnic->own_if.size = sizeof(SshVnicDrvIfStruct);
      vnic->own_if.cb_context = vnic;
      vnic->own_if.connect_cb = ssh_vnic_icept_connect;
      vnic->own_if.disconnect_cb = ssh_vnic_icept_disconnect;
      vnic->own_if.enable_cb = ssh_vnic_enable;
      vnic->own_if.disable_cb = ssh_vnic_disable;
      vnic->own_if.configure_cb = ssh_vnic_configure;
      vnic->own_if.receive_cb = ssh_vnic_receive;

      vnic->connect_status = SSH_VNIC_INITIAL_MEDIA_STATE;

      vnic->initialized = TRUE;
    }

  InterlockedExchange(&vnic->pending_operations, 0);
  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_INITIALIZING);

  NdisZeroMemory(&reg_attrs, sizeof(reg_attrs));
  NdisZeroMemory(&gen_attrs, sizeof(gen_attrs));

  /* Set registration attributes */
  reg_attrs.Header.Type =
    NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;

#if (NDIS_SUPPORT_NDIS630)
  reg_attrs.Header.Revision =
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
  reg_attrs.Header.Size =
    NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
#else
  reg_attrs.Header.Revision =
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
  reg_attrs.Header.Size =
    NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
#endif

  reg_attrs.MiniportAdapterContext = (NDIS_HANDLE)vnic;
  reg_attrs.AttributeFlags = 0;
  reg_attrs.CheckForHangTimeInSeconds = 60;
  reg_attrs.InterfaceType = NdisInterfaceInternal;

  status =
   NdisMSetMiniportAttributes(adapter_handle,
                              (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&reg_attrs);
  if (status != NDIS_STATUS_SUCCESS)
    goto failed;

  /* Set generic attributes */
  gen_attrs.Header.Type =
    NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;

#if (NDIS_SUPPORT_NDIS620)
  gen_attrs.Header.Revision =
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
  gen_attrs.Header.Size =
    NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
#else
  gen_attrs.Header.Revision =
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
  gen_attrs.Header.Size =
    NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
#endif

  gen_attrs.MediaType = SSH_VNIC_MEDIUM;
  gen_attrs.PhysicalMediumType = NdisPhysicalMediumUnspecified;
  gen_attrs.MtuSize = SSH_DEFAULT_MTU;
  gen_attrs.MaxXmitLinkSpeed =
  gen_attrs.XmitLinkSpeed =
  gen_attrs.MaxRcvLinkSpeed =
  gen_attrs.RcvLinkSpeed = SSH_VNIC_LINK_SPEED;
  gen_attrs.MediaConnectState = vnic->connect_status;
  gen_attrs.MediaDuplexState = MediaDuplexStateFull;
  gen_attrs.LookaheadSize = SSH_DEFAULT_MTU;
  gen_attrs.PowerManagementCapabilities = NULL;
#if (NDIS_SUPPORT_NDIS620)
  gen_attrs.PowerManagementCapabilitiesEx = NULL;
#endif

  gen_attrs.MacOptions = SSH_VNIC_MAC_OPTIONS;
  gen_attrs.SupportedPacketFilters = SSH_VNIC_SUPPORTED_PACKET_FILTERS;
  gen_attrs.MaxMulticastListSize = SSH_VNIC_MAX_MULTICAST_ADDRESSES;
  gen_attrs.MacAddressLength = 6;
  NdisMoveMemory(gen_attrs.PermanentMacAddress, vnic->mac_address, 6);
  NdisMoveMemory(gen_attrs.CurrentMacAddress, vnic->mac_address, 6);
  gen_attrs.RecvScaleCapabilities = NULL;
  gen_attrs.AccessType = NET_IF_ACCESS_BROADCAST;
  gen_attrs.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
  gen_attrs.ConnectionType = NET_IF_CONNECTION_DEDICATED;
  gen_attrs.IfType = IF_TYPE_ETHERNET_CSMACD;
  gen_attrs.IfConnectorPresent = TRUE;
  gen_attrs.SupportedStatistics = SSH_VNIC_SUPPORTED_STATISTICS;
  gen_attrs.SupportedPauseFunctions = NdisPauseFunctionsUnknown;
  gen_attrs.DataBackFillSize = 1500 - SSH_DEFAULT_MTU;
  gen_attrs.ContextBackFillSize = 0;
  gen_attrs.SupportedOidList = ssh_vnic_supported_oids;
  gen_attrs.SupportedOidListLength = sizeof(ssh_vnic_supported_oids);

  status =
   NdisMSetMiniportAttributes(adapter_handle,
                              (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen_attrs);
  if (status != NDIS_STATUS_SUCCESS)
    goto failed;

  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_PAUSED);
  return status;

 failed:

  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_HALTED);
  InterlockedDecrement(&vnic_instances);
  NdisZeroMemory(vnic, sizeof(*vnic));
  return status;
}


/*-------------------------------------------------------------------------
  ssh_vnic_pause()
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_pause(NDIS_HANDLE adapter_context,
               PNDIS_MINIPORT_PAUSE_PARAMETERS params)
{
  SshVnic vnic = (SshVnic)adapter_context;

  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_PAUSING);

  while (InterlockedCompareExchange(&vnic->pending_operations, 0, 0))
    NdisMSleep(1000);

  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_PAUSED);

  return NDIS_STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------
  ssh_vnic_restart()
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_restart(NDIS_HANDLE adapter_context,
                 PNDIS_MINIPORT_RESTART_PARAMETERS params)
{
  SshVnic vnic = (SshVnic)adapter_context;

  InterlockedExchange(&vnic->state, SSH_VNIC_STATE_RUNNING);

  return NDIS_STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------
  ssh_vnic_query information()
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_query_information(SshVnic vnic,
                           NDIS_OID oid,
                           PVOID information_buffer,
                           ULONG information_buffer_length,
                           PULONG bytes_written,
                           PULONG bytes_needed)
{
  ULONG ulong_value;
  USHORT ushort_value;
  void *info = &ulong_value;
  ULONG info_len = sizeof(ulong_value);
  ULONG info_bytes_available = info_len;
  NDIS_HARDWARE_STATUS hw_status;
  NDIS_MEDIUM medium;
  NDIS_PHYSICAL_MEDIUM phys_medium;

  /* initialize return values to something legal */
  *bytes_written = 0;
  *bytes_needed = 0;

  switch (oid)
    {
    case OID_GEN_SUPPORTED_GUIDS:
      info = ssh_vnic_supported_guids;
      info_bytes_available = info_len = sizeof(ssh_vnic_supported_guids);
      break;

    /* General Operational Characteristics */
    case OID_GEN_SUPPORTED_LIST:
      info = ssh_vnic_supported_oids;
      info_bytes_available = info_len = sizeof(ssh_vnic_supported_oids);
      break;

    case OID_GEN_HARDWARE_STATUS:
      if (SSH_VNIC_IS_ENABLED(vnic))
        hw_status = NdisHardwareStatusReady;
      else
        hw_status = NdisHardwareStatusNotReady;
      info = &hw_status;
      info_bytes_available = info_len = sizeof(hw_status);
      break;

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:
      medium = SSH_VNIC_MEDIUM;
      info = &medium;
      info_bytes_available = info_len = sizeof(medium);
      break;

    case OID_GEN_PHYSICAL_MEDIUM:
      phys_medium = NdisPhysicalMediumUnspecified;
      info = &phys_medium;
      info_bytes_available = info_len = sizeof(phys_medium);
      break;

    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_MAXIMUM_FRAME_SIZE:
    case OID_GEN_CURRENT_LOOKAHEAD:
      ulong_value = SSH_DEFAULT_MTU;
      break;

    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      ulong_value = SSH_MAXIMUM_PACKET_SIZE;
      break;

    case OID_GEN_MAC_OPTIONS:
      ulong_value = SSH_VNIC_MAC_OPTIONS;
      break;

    case OID_GEN_LINK_SPEED:
      ulong_value = SSH_VNIC_LINK_SPEED / 100;
      break;

    case OID_GEN_MEDIA_CONNECT_STATUS:
      info = &vnic->connect_status;
      info_bytes_available = info_len = sizeof(vnic->connect_status);
      break;

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      ulong_value = SSH_VNIC_BUFFER_SPACE;
      break;

    case OID_GEN_VENDOR_ID:
      ulong_value = 0xFFFFFF; /* three-byte IEEE-registered vendor code */
      break;

    case OID_GEN_VENDOR_DESCRIPTION:
      info = (void *)vendor_description;
      info_bytes_available = info_len = sizeof(vendor_description);
      break;

    case OID_GEN_VENDOR_DRIVER_VERSION:
      ulong_value = SSH_VENDOR_DRIVER_VERSION;
      break;

    case OID_GEN_DRIVER_VERSION:
      ushort_value = (SSH_VNIC_NDIS_MAJOR_VERSION << 8)
                      | SSH_VNIC_NDIS_MINOR_VERSION;
      info = &ushort_value;
      info_bytes_available = info_len = sizeof(ushort_value);
      break;

    case OID_GEN_CURRENT_PACKET_FILTER:
      ulong_value = vnic->packet_filter;
      break;

    case OID_GEN_MAXIMUM_SEND_PACKETS:
      ulong_value = SSH_VNIC_MAXIMUM_SEND_PACKETS;
      break;

      /* General Statistics */
    case OID_GEN_XMIT_OK:
      info_bytes_available = sizeof(vnic->good_transmits);
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->good_transmits;
        }
      else
        {
          /* Return 32-bit value */
          info = &vnic->good_transmits;
          info_len = info_bytes_available;
        }
      break;

    case OID_GEN_RCV_OK:
      info_bytes_available = sizeof(vnic->good_receives);
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->good_receives;
        }
      else
        {
          /* Return 64-bit value */
          info = &vnic->good_receives;
          info_len = info_bytes_available;
        }
      break;

    case OID_GEN_XMIT_ERROR:
      info_bytes_available = sizeof(vnic->bad_transmits);
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_transmits;
        }
      else
        {
          /* Return 64-bit value */
          info = &vnic->bad_transmits;
          info_len = info_bytes_available;
        }
      break;

    case OID_GEN_RCV_ERROR:
      info_bytes_available = sizeof(vnic->bad_receives);
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_receives;
        }
      else
        {
          /* Return 64-bit value */
          info = &vnic->bad_receives;
          info_len = info_bytes_available;
        }
      break;

    case OID_GEN_RCV_NO_BUFFER:
      info_bytes_available = sizeof(vnic->bad_receives_no_buffer);
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_receives_no_buffer;
        }
      else
        {
          /* Return 64-bit value */
          info = &vnic->bad_receives_no_buffer;
          info_len = info_bytes_available;
        }
      break;

    case OID_GEN_DIRECTED_BYTES_XMIT: /* optional oids - not supported */
    case OID_GEN_DIRECTED_FRAMES_XMIT:
    case OID_GEN_MULTICAST_BYTES_XMIT:
    case OID_GEN_MULTICAST_FRAMES_XMIT:
    case OID_GEN_BROADCAST_BYTES_XMIT:
    case OID_GEN_BROADCAST_FRAMES_XMIT:
    case OID_GEN_DIRECTED_BYTES_RCV:
    case OID_GEN_DIRECTED_FRAMES_RCV:
    case OID_GEN_MULTICAST_BYTES_RCV:
    case OID_GEN_MULTICAST_FRAMES_RCV:
    case OID_GEN_BROADCAST_BYTES_RCV:
    case OID_GEN_BROADCAST_FRAMES_RCV:
    case OID_GEN_RCV_CRC_ERROR:
    case OID_GEN_TRANSMIT_QUEUE_LENGTH:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* Ethernet Objects */

      /* operational oids */
    case OID_802_3_PERMANENT_ADDRESS:
    case OID_802_3_CURRENT_ADDRESS:
      info = vnic->mac_address;
      info_bytes_available = info_len = sizeof(vnic->mac_address);
      break;

    case OID_802_3_MULTICAST_LIST:
      info = vnic->multicast_addresses;
      info_bytes_available =
      info_len = sizeof(EthernetAddress) * vnic->nbr_of_mc_addresses;
      break;

    case OID_802_3_MAXIMUM_LIST_SIZE:
      ulong_value = SSH_VNIC_MAX_MULTICAST_ADDRESSES;
      break;

    case OID_802_3_MAC_OPTIONS: /* optional */
      ulong_value = 0; /* we could emulate some MAC options ...*/
      break;

      /* mandatory statistical oids */
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
      ulong_value = 0; /* no faults in the virtual world... */
      break;

      /* optional statistical oids */
    case OID_802_3_XMIT_DEFERRED:
    case OID_802_3_XMIT_MAX_COLLISIONS:
    case OID_802_3_RCV_OVERRUN:
    case OID_802_3_XMIT_UNDERRUN:
    case OID_802_3_XMIT_HEARTBEAT_FAILURE:
    case OID_802_3_XMIT_TIMES_CRS_LOST:
    case OID_802_3_XMIT_LATE_COLLISIONS:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* Plug-and-Play and Power-Management Objects */

      /* operational oids, all are optional */
    case OID_PNP_CAPABILITIES:
      info = (void *)&ssh_vnic_pnp_capabilities;
      info_bytes_available = info_len = sizeof(ssh_vnic_pnp_capabilities);
      break;

    case OID_PNP_QUERY_POWER:
      *bytes_written = 0;
      return NDIS_STATUS_SUCCESS;

    case OID_PNP_WAKE_UP_PATTERN_LIST:
    case OID_PNP_ENABLE_WAKE_UP:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* statistical oids, both are optional */
    case OID_PNP_WAKE_UP_ERROR:
    case OID_PNP_WAKE_UP_OK:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* custom oid */
    case OID_SSH_QUERY_INTERFACE:
      info = &vnic->own_if;
      info_bytes_available = info_len = sizeof(vnic->own_if);
      break;

    default:
      return NDIS_STATUS_NOT_SUPPORTED;
    }

  *bytes_needed = info_bytes_available;
  if (info_len <= information_buffer_length)
    {
      *bytes_written = info_len;
      NdisMoveMemory(information_buffer, info, info_len);
      return NDIS_STATUS_SUCCESS;
    }
  else
    {
      *bytes_needed = info_len;
      return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
}


/*-------------------------------------------------------------------------
  ssh_vnic_set_information()
  -------------------------------------------------------------------------*/
NDIS_STATUS
ssh_vnic_set_information(SshVnic vnic,
                         NDIS_OID oid,
                         PVOID information_buffer,
                         ULONG buffer_length,
                         PULONG bytes_read,
                         PULONG bytes_needed)
{
  ULONG *ul_info = (ULONG *)information_buffer;

  *bytes_read = 0;
  *bytes_needed = 0;

  switch (oid)
    {
    /* General Objects */
    case OID_GEN_CURRENT_PACKET_FILTER:
      if (buffer_length != sizeof(ULONG))
        return NDIS_STATUS_INVALID_LENGTH;
      vnic->packet_filter = *ul_info;
      return NDIS_STATUS_SUCCESS;

    case OID_GEN_CURRENT_LOOKAHEAD:
      if (buffer_length != sizeof(ULONG))
        return NDIS_STATUS_INVALID_LENGTH;
      vnic->lookahead_size = *ul_info;
      return NDIS_STATUS_SUCCESS;

    case OID_GEN_PROTOCOL_OPTIONS:
      if (buffer_length != sizeof(ULONG))
        return NDIS_STATUS_INVALID_LENGTH;
      vnic->protocol_options = *ul_info;
      return NDIS_STATUS_SUCCESS;

    case OID_GEN_NETWORK_LAYER_ADDRESSES:
    case OID_GEN_TRANSPORT_HEADER_OFFSET:
      *bytes_read = buffer_length;
      return NDIS_STATUS_SUCCESS;

      /* Ethernet Objects */
    case OID_802_3_MULTICAST_LIST:
      if (buffer_length % sizeof(EthernetAddress) != 0)
        return NDIS_STATUS_INVALID_LENGTH;

      if (buffer_length / sizeof(EthernetAddress) >
                                            SSH_VNIC_MAX_MULTICAST_ADDRESSES)
        return NDIS_STATUS_INVALID_DATA;

      NdisMoveMemory(vnic->multicast_addresses,
                     information_buffer,
                     buffer_length);

      vnic->nbr_of_mc_addresses = buffer_length / sizeof(EthernetAddress);

      *bytes_read = buffer_length;
      return NDIS_STATUS_SUCCESS;

      /* Plug-and-Play and Power Management */
    case OID_PNP_ADD_WAKE_UP_PATTERN:
    case OID_PNP_ENABLE_WAKE_UP:
    case OID_PNP_REMOVE_WAKE_UP_PATTERN:
      return NDIS_STATUS_NOT_SUPPORTED;

    case OID_PNP_SET_POWER:
      *bytes_read = buffer_length;
      return NDIS_STATUS_SUCCESS;

      /* Task Offload Objects */
    case OID_TCP_TASK_OFFLOAD:
    case OID_TCP_TASK_IPSEC_ADD_SA:
    case OID_TCP_TASK_IPSEC_DELETE_SA:
    default:
      return NDIS_STATUS_NOT_SUPPORTED;
    }  /* switch (oid) */
}


/*-------------------------------------------------------------------------
  ssh_vnic_oid_request()
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_oid_request(NDIS_HANDLE adapter_context,
                     PNDIS_OID_REQUEST request)
{
  SshVnic vnic = (SshVnic)adapter_context;
  NDIS_STATUS status;

  switch (request->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
      status =
        ssh_vnic_query_information(vnic,
                     request->DATA.QUERY_INFORMATION.Oid,
                     request->DATA.QUERY_INFORMATION.InformationBuffer,
                     request->DATA.QUERY_INFORMATION.InformationBufferLength,
                     &request->DATA.QUERY_INFORMATION.BytesWritten,
                     &request->DATA.QUERY_INFORMATION.BytesNeeded);
      break;

    case NdisRequestSetInformation:
      status = ssh_vnic_set_information(vnic,
                     request->DATA.SET_INFORMATION.Oid,
                     request->DATA.SET_INFORMATION.InformationBuffer,
                     request->DATA.SET_INFORMATION.InformationBufferLength,
                     &request->DATA.SET_INFORMATION.BytesRead,
                     &request->DATA.SET_INFORMATION.BytesNeeded);
      break;

    default:
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
    }

  return status;
}


/*-------------------------------------------------------------------------
  ssh_vnic_cancel_oid_request()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_cancel_oid_request(NDIS_HANDLE adapter_context,
                            PVOID request_id)
{
  /* We complete all requests synchronously so there is nothing to cancel */
}


/*-------------------------------------------------------------------------
  ssh_vnic_send()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_send(NDIS_HANDLE adapter_context,
              PNET_BUFFER_LIST net_buffer_lists,
              NDIS_PORT_NUMBER port_number,
              ULONG send_flags)
{
  SshVnic vnic = (SshVnic)adapter_context;
  SshIceptDrvIf icept_if;
  BOOLEAN is_dispatch_level =
    (send_flags & NDIS_SEND_FLAGS_DISPATCH_LEVEL) ? TRUE : FALSE;

  if (net_buffer_lists == NULL)
    return;

  /* Drop the packets if we are not in running state */
  if (vnic->state != SSH_VNIC_STATE_RUNNING)
    {
      /* mark all NBL with NDIS_STATUS_PAUSED before completion */
      PNET_BUFFER_LIST nbl = net_buffer_lists;
      while (nbl)
        {
          NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_PAUSED;
          nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
        }
      NdisMSendNetBufferListsComplete(vnic->miniport_handle,
        net_buffer_lists,
        is_dispatch_level ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);

      return;
    }

  InterlockedIncrement(&vnic->pending_operations);

  icept_if = ssh_vnic_interceptor_if_get(vnic, FALSE);
  if (icept_if != NULL)
    {
      PNET_BUFFER_LIST nbl = net_buffer_lists;

      while (nbl)
        {
          PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

          while (nb)
            {
              unsigned char *data;
              unsigned char *src_buffer;
              unsigned char *dst;
              ULONG src_len;
              PMDL mdl;
              ULONG len = NET_BUFFER_DATA_LENGTH(nb);
              ULONG bytes_left = len;
              ULONG offset;






              data = ssh_vnic_alloc(len);
              if (data == NULL)
                break;

              mdl = NET_BUFFER_CURRENT_MDL(nb);

              /* Skip back fill space from the beginning of first MDL */
              offset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);

              /* Copy data from MDLs to one linear buffer */
              dst = data;
              while (mdl && bytes_left)
                {
                  NdisQueryMdl(mdl, &src_buffer, &src_len, LowPagePriority);
                  if (src_buffer == NULL)
                    goto free_buffer;

                  if (offset)
                    {
                      src_buffer += offset;
                      src_len -= offset;
                      offset = 0;
                    }

                  if (src_len > bytes_left)
                    src_len = bytes_left;

                  NdisMoveMemory(dst, src_buffer, src_len);
                  dst += src_len;
                  bytes_left -= src_len;

                  NdisGetNextMdl(mdl, &mdl);
                }

              /* If we are in promiscuous mode, we should loopback the packet,
                 otherwise network monitoring tools don't see our "sends". */
              if (vnic->packet_filter & NDIS_PACKET_TYPE_PROMISCUOUS)
                ssh_vnic_receive(vnic, data, len);

              (*icept_if->send_cb)(icept_if->cb_context, data, len);

 free_buffer:
              ssh_vnic_free(data);

              nb = NET_BUFFER_NEXT_NB(nb);
            };

          NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;
          nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
        };

      (*icept_if->release_cb)(icept_if->cb_context);
    }

  NdisMSendNetBufferListsComplete(vnic->miniport_handle,
    net_buffer_lists,
    is_dispatch_level ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);

  InterlockedDecrement(&vnic->pending_operations);
}


/*-------------------------------------------------------------------------
  ssh_vnic_cancel_send()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_cancel_send(NDIS_HANDLE adapter_context,
                     PVOID cancel_id)
{
  /* We don't support send request cancellation */
}


/*-------------------------------------------------------------------------
  ssh_vnic_return_nbls()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_return_nbls(NDIS_HANDLE adapter_context,
                     PNET_BUFFER_LIST net_buffer_lists,
                     ULONG return_flags)
{
  /* Receives are always completed synchronously so this function should
     never be called. */
  ASSERT(FALSE);
}


/*-------------------------------------------------------------------------
  ssh_vnic_check_for_hang()
  -------------------------------------------------------------------------*/
static BOOLEAN
ssh_vnic_check_for_hang(NDIS_HANDLE adapter_context)
{
  return FALSE;
}


/*-------------------------------------------------------------------------
  ssh_vnic_reset()
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_reset(NDIS_HANDLE adapter_context,
               PBOOLEAN addressing_reset)
{
  if (addressing_reset != NULL)
    *addressing_reset = FALSE;

  return NDIS_STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------
  ssh_vnic_pnp_event_notify()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_pnp_event_notify(NDIS_HANDLE adapter_context,
                          PNET_DEVICE_PNP_EVENT pnp_event)
{
}


/*-------------------------------------------------------------------------
  ssh_vnic_halt()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_halt(NDIS_HANDLE adapter_context,
              NDIS_HALT_ACTION action)
{
  SshVnic vnic = (SshVnic)adapter_context;

  if (action != NdisHaltDevicePoweredDown)
    {
      NdisFreeSpinLock(&vnic->icept_if_lock);
      NdisFreeSpinLock(&vnic->lock);

      NdisZeroMemory(vnic, sizeof(*vnic));

      InterlockedDecrement(&vnic_instances);
    }
}


/*-------------------------------------------------------------------------
  ssh_vnic_shutdown()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_shutdown(NDIS_HANDLE adapter_context,
                  NDIS_SHUTDOWN_ACTION action)
{
  /* Nothing to do */
}


/*-------------------------------------------------------------------------
  ssh_vnic_unload()
  -------------------------------------------------------------------------*/
static VOID
ssh_vnic_unload(PDRIVER_OBJECT driver_object)
{
  if (vnic_device_handle)
    NdisDeregisterDeviceEx(vnic_device_handle);

  NdisMDeregisterMiniportDriver(vnic_driver_handle);
}



#pragma NDIS_PAGEABLE_FUNCTION(ssh_vnic_dispatch)

NTSTATUS
ssh_vnic_dispatch(PDEVICE_OBJECT device,
                  PIRP irp)
{
  NTSTATUS  status = STATUS_UNSUCCESSFUL;
  PIO_STACK_LOCATION  irp_stack;
  ULONG  buff_len;
  PVOID  buffer;

  PAGED_CODE();

  irp_stack = IoGetCurrentIrpStackLocation(irp);

  irp->IoStatus.Information = 0;

  switch (irp_stack->MajorFunction)
    {
    case IRP_MJ_CREATE:
      status = STATUS_SUCCESS;
      break;

    case IRP_MJ_CLEANUP:
      status = STATUS_SUCCESS;
      break;

    case IRP_MJ_CLOSE:
      status = STATUS_SUCCESS;
      break;

    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
      switch (irp_stack->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_SSH_QUERY_INTERFACE:
          buffer = irp->AssociatedIrp.SystemBuffer;
          buff_len = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;
          if (buff_len >= sizeof(own_if))
            {
              NdisMoveMemory(buffer, &own_if, sizeof(own_if));
              irp->IoStatus.Information = sizeof(own_if);
              status = STATUS_SUCCESS;
            }
          else
            {
              irp->IoStatus.Information = sizeof(own_if);
              status = STATUS_BUFFER_TOO_SMALL;
            }
          break;

        default:
          break;
        }

    default:
        break;
    }

  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  return status;
}


/*---------- Private interface for QuickSec packet interceptor ----------*/

/*-------------------------------------------------------------------------
  ssh_vnic_icept_connect()

  Interceptor opens connection to virtual NIC by calling this function.

  During connection establish virtual NIC makes a callback call to
  interceptor's side and locks the 'virtual adapter' (by reference counting)
  so that it can be not released while the connection exists.

  Postcondition:

  Vnic can call callback functions on interceptor's side.
  Virtual adapter on the interceptors side is 'locked'.

  Arguments:
    vnic - points to virtual NIC's context structure.
    icept_if - points to interceptor interface structure (i.e. the private
               funtions virtual NIC is "allowed" to call).

  Returns:
    TRUE is icept_if is a valid interface,
    FALSE otherwise
  -------------------------------------------------------------------------*/
static BOOLEAN
ssh_vnic_icept_connect(SshVnic vnic,
                       SshIceptDrvIf icept_if)
{
  BOOLEAN success = FALSE;

  if ((icept_if != NULL) &&
      (icept_if->signature == SSH_ICEPT_VNIC_SIGNATURE) &&
      (icept_if->lock_cb != NULL) &&
      (icept_if->release_cb != NULL))
    {
      /* "Lock" the provided interface, so it won't be deleted without
         our permission */
      (*icept_if->lock_cb)(icept_if->cb_context);

      /* Now we can begin to use this interface */
      NdisAcquireSpinLock(&vnic->icept_if_lock);
      vnic->icept_if = icept_if;
      NdisReleaseSpinLock(&vnic->icept_if_lock);

      success = TRUE;
    }

  return success;
}

static void *
ssh_vnic_icept_connect_v2(SshVnicConnectId vnic_id,
                          SshIceptDrvIf icept_if)
{
  SshVnic vnic = NULL;
  ULONG i;

  if ((vnic_id == NULL) || (icept_if == NULL))
    return NULL;

  switch (vnic_id->type)
    {
    case VNIC_CONNECT_ID_MEDIA_ADDRESS:
      if (vnic_id->media_addr.addr_len != ETH_LENGTH_OF_ADDRESS)
        break;

      for (i = 0; i < SSH_MAX_VNIC_INSTANCES; i++)
        {
          if (vnic_table[i].initialized == FALSE)
            continue;

          if (NdisEqualMemory(&vnic_table[i].mac_address,
                              vnic_id->media_addr.addr,
                              vnic_id->media_addr.addr_len))
            {
              if (ssh_vnic_icept_connect(&vnic_table[i], icept_if))
                vnic = &vnic_table[i];

              break;
            }
        }
      break;

    default:
      break;
    }

  return vnic;
}


/*-------------------------------------------------------------------------
  ssh_vnic_icept_disconnect()

  Releases the connection between vnic and the SSH packet interceptor
  driver.

  Arguments:
    vnic - pointes to virtual NIC's context structure.
  -------------------------------------------------------------------------*/
static void
ssh_vnic_icept_disconnect(SshVnic vnic)
{
  /* Get the interface and remove it from our own data structure (this is
     an atomic operation protected by a spin lock) */
  SshIceptDrvIf icept_if = ssh_vnic_interceptor_if_get(vnic, TRUE);

  /* We don't need to call release callback twice, because
     ssh_vnic_interceptor_if_get doesn't call lock callback when we
     specify TRUE as the 'remove' argument */
  if (icept_if)
    (*icept_if->release_cb)(icept_if->cb_context);
}


/*-------------------------------------------------------------------------
  ssh_vnic_enable()

  Interceptor uses this function to enable (plug-in) the virtual adapter.

  Arguments:
    vnic - points to virtual NIC's context structure.

  Returns:
    TRUE
  -------------------------------------------------------------------------*/
static BOOLEAN
ssh_vnic_enable(SshVnic vnic)
{
  ssh_vnic_switch_connect_status(vnic, MediaConnectStateConnected);

  return (TRUE);
}


/*-------------------------------------------------------------------------
   ssh_vnic_disable()

   Interceptor uses this function to disable vnic. This is
   normally done when 'virtual adapter' abstraction is
   destroyed (during VPN connection shutdown).

   Arguments:

   'vnic' points to callback context structure.
  -------------------------------------------------------------------------*/
static void
ssh_vnic_disable(SshVnic vnic)
{
  ssh_vnic_switch_connect_status(vnic, MediaConnectStateDisconnected);
}


/*-------------------------------------------------------------------------
  ssh_vnic_configure()

  This interface function allows SSH packet interceptor driver to configure
  the attached virtual NIC. Currently this function does nothing.

  Arguments:
    vnic - points to virtual NIC's context structure.
    type - type of configuration request
    data - points to a buffer containing configuration data
  -------------------------------------------------------------------------*/
static BOOLEAN
ssh_vnic_configure(SshVnic vnic,
                   UINT type,
                   void * data)
{
  BOOLEAN success = FALSE;

  switch (type)
    {
    case SSH_VNIC_CONF_ETH_ADDRESS:
    default:
      break;
    }

  return success;
}


/*-------------------------------------------------------------------------
  ssh_vnic_receive()

  Interceptor uses this function to indicate the protocol a packet
  that was "received" by a virtual adapter.

  Arguments:
    vnic - points to virtual NIC's context structure.
    buffer - points to buffer containing the "received" message (buffer
             must contain an ehthernet frame including all headers).
    buffer_len - length (in bytes) of the "received frame".

  Notes:
    This function is also called internally by virtual NIC, when the VNIC
    is in promiscuous mode.
  -------------------------------------------------------------------------*/
void
ssh_vnic_receive(SshVnic vnic,
                 unsigned char *buffer,
                 unsigned int buffer_len)
{
  NET_BUFFER_LIST nbl;
  NET_BUFFER nb;
  PMDL mdl;

  mdl = IoAllocateMdl(buffer, buffer_len, FALSE, FALSE, NULL);
  if (mdl == NULL)
    {
      vnic->bad_receives++;
      return;
    }

  MmBuildMdlForNonPagedPool(mdl);

  /* Build a fake NET_BUFFER_LIST */
  NdisZeroMemory(&nb, sizeof(nb));
  NET_BUFFER_CURRENT_MDL(&nb) = mdl;
  NET_BUFFER_FIRST_MDL(&nb) = mdl;
  NET_BUFFER_CURRENT_MDL_OFFSET(&nb) = 0;
  NET_BUFFER_DATA_OFFSET(&nb) = 0;
  NET_BUFFER_DATA_LENGTH(&nb) = buffer_len;

  NdisZeroMemory(&nbl, sizeof(nbl));
  NdisSetNetBufferListProtocolId(&nbl, NDIS_PROTOCOL_ID_TCP_IP);
  NET_BUFFER_LIST_FIRST_NB(&nbl) = &nb;

  InterlockedIncrement(&vnic->pending_operations);

  /* Silently drop the packet if we are not in running state */
  if (vnic->state == SSH_VNIC_STATE_RUNNING)
    {
      /* Set the 'NO_RESOURCES' flag to ensure that receive completes
         synchronously. */
      NdisMIndicateReceiveNetBufferLists(vnic->miniport_handle,
                                         &nbl,
                                         0,
                                         1,
                                         NDIS_RECEIVE_FLAGS_RESOURCES);

      vnic->good_receives++;
    }

  InterlockedDecrement(&vnic->pending_operations);

  IoFreeMdl(mdl);
}


/*-------------------------------------------------------------------
  PRIVATE FUNCTIONS
  -------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_vnic_interceptor_if_get()

  Returns a pointer to the SSH packet interceptor interface.

  If 'remove' is FALSE, reference count of the connected 'virtual_adapter'
  is incremented (by calling 'lock_cb' of the interceptor interface).

  If 'remove' is TRUE, ssh_vnic_interceptor_if_get() removes the interceptor
  interface from virtual NIC's context structure (so the interface can not
  be retrieved any more).

  The caller of ssh_vnic_interceptor_if_get() _must_ decrement interceptor
  interface's reference count by calling 'release_cb' after the interface
  is not needed any more.

  Returns:
    A pointer to the interface structure or NULL if the interceptor is
    not currently connected to virtual NIC.
  -------------------------------------------------------------------------*/
static SshIceptDrvIf __fastcall
ssh_vnic_interceptor_if_get(SshVnic vnic,
                            BOOLEAN remove)
{
  SshIceptDrvIf icept_if;

  NdisAcquireSpinLock(&vnic->icept_if_lock);

  icept_if = vnic->icept_if;

  if (remove == TRUE)
    {
      vnic->icept_if = NULL;

      /* If locking is in progress, we have to delay our release (otherwice
         we´ll cause a race condition...) */
      if (vnic->locking_in_progress == TRUE)
        icept_if = NULL;
    }
  else if (icept_if != NULL)
    vnic->locking_in_progress = TRUE;

  NdisReleaseSpinLock(&vnic->icept_if_lock);

  if ((remove == FALSE) && (icept_if != NULL))
    {
      BOOLEAN delayed_release = FALSE;

      /* Increment the reference count */
      (*icept_if->lock_cb)(icept_if->cb_context);

      NdisAcquireSpinLock(&vnic->icept_if_lock);
      vnic->locking_in_progress = FALSE;

      /* If interceptor_if is NULL now, it means that "interceptor
         disconnect" has been called at the time we were executing lock_cb
         To prevent memory leak, WE must call the release now */
      if (vnic->icept_if == NULL)
        delayed_release = TRUE;

      NdisReleaseSpinLock(&vnic->icept_if_lock);

      if (delayed_release == TRUE)
        {
          (*icept_if->release_cb)(icept_if->cb_context);
          icept_if = NULL; /* return null because we have disconnected */
        }
    }

  return (icept_if);
}


/*-------------------------------------------------------------------------
  ssh_vnic_switch_connect_status()

  Switch connection status of adapter to 'new_state'. Valid states are
  NdisMediaStateConnected and NdisMediaStateDisconnected.

  If state of the adapter is changed due to this call, the new state
  is indicated to NDIS using NdisMIndicateStatus().

  Arguments:
    vnic - points to virtual NIC's context structure.
    new_state - desired state.

  Returns:
    NDIS_STATUS_SUCCESS
    NDIS_STATUS_INVALID_DATA - 'new_state' is invalid
  -------------------------------------------------------------------------*/
static NDIS_STATUS __fastcall
ssh_vnic_switch_connect_status(SshVnic vnic,
                               NDIS_MEDIA_STATE new_state)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  if (new_state == vnic->connect_status)
    {
      /* nothing to change */
      return NDIS_STATUS_SUCCESS;
    }

  InterlockedIncrement(&vnic->pending_operations);

  if ((new_state == MediaConnectStateConnected) ||
      (new_state == MediaConnectStateDisconnected))
    {
      NDIS_STATUS_INDICATION indication;

      vnic->connect_status = new_state;

      NdisZeroMemory(&indication, sizeof(indication));
      indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
      indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
      indication.Header.Size = sizeof(indication);
      indication.SourceHandle = vnic->miniport_handle;
      indication.PortNumber = 0;
      if (vnic->connect_status == MediaConnectStateConnected)
        indication.StatusCode = NDIS_STATUS_MEDIA_CONNECT;
      else
        indication.StatusCode = NDIS_STATUS_MEDIA_DISCONNECT;
      indication.StatusBuffer = NULL;
      indication.StatusBufferSize = 0;
      indication.Flags = 0;
      indication.DestinationHandle = NULL;
      indication.RequestId = NULL;

      switch (vnic->state)
        {
        case SSH_VNIC_STATE_PAUSED:
        case SSH_VNIC_STATE_RESTARTING:
        case SSH_VNIC_STATE_RUNNING:
        case SSH_VNIC_STATE_PAUSING:
          NdisMIndicateStatusEx(vnic->miniport_handle, &indication);
          break;
        }
    }
  else
    {
      status = NDIS_STATUS_INVALID_DATA;
    }

  InterlockedDecrement(&vnic->pending_operations);

  return status;
}



/*--------------------------------------------------------------------------
  ssh_vnic_alloc()

  Allocates a new memory block.

  Arguments:
    size  - size (in bytes) of memory block to be allocated

  Returns:
    Either a valid pointer to the allocated memory block or NULL if the
    allocation request cannot be satisfied for some reason.
  --------------------------------------------------------------------------*/
#pragma warning(disable: 6011 6014)
static void *
ssh_vnic_alloc(ULONG size)
{
  char * addr;

  if (NdisAllocateMemoryWithTag(&addr, size + sizeof(unsigned long),
                                'TNFS') != NDIS_STATUS_SUCCESS)
    return NULL;

  *(unsigned long*)addr = size;

  return (void*)(addr + sizeof(unsigned long));
}
#pragma warning(default: 6011 6014)


/*-------------------------------------------------------------------------
  ssh_vnic_free()

  Frees a previously allocated block of memory.

  Arguments:
    addr  - pointer to memory block to be freed.
  -------------------------------------------------------------------------*/
void
ssh_vnic_free(void * addr)
{
  unsigned long size;

  addr = (unsigned char *)addr - sizeof(unsigned long);
  size = *(unsigned long*)addr;

  ASSERT(size != SSH_MEM_BLOCK_HAS_BEEN_FREED);
  *(unsigned long*)addr = SSH_MEM_BLOCK_HAS_BEEN_FREED;

  size += sizeof(unsigned long);
  NdisFreeMemory(addr, size, 0);
}


