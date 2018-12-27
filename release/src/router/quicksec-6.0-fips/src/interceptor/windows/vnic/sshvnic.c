/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VNIC, virtual network interface for implementing virtual-IP feature
   on Windows platforms.

   Virtual NIC is implemented as a NDIS miniport driver
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/

#include "sshincludes.h"
#include <ndis.h>
#include "sshvnic.h"
#include "sshvnicdbg.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* This definition limits the amount of virtual NIC instances can be created.
   You may increase this value when necessary. Note, however, that "too many"
   virtual adapters could cause us to run out of NonPagedPool if the packet
   interceptor is allocating packet pools per adapter basis. */
#define SSH_MAX_VNIC_INSTANCES        10

#if defined NDIS51_MINIPORT
#define SSH_VNIC_NDIS_MAJOR_VERSION   5
#define SSH_VNIC_NDIS_MINOR_VERSION   1
#elif defined NDIS50_MINIPORT
#define SSH_VNIC_NDIS_MAJOR_VERSION   5
#define SSH_VNIC_NDIS_MINOR_VERSION   0
#else 
#error "legacy NDIS versions not supported any more"
#endif

#define ETHERNET_HEADER_SIZE          14
#define MAXIMUM_ETHERNET_PACKET_SIZE  1414  

#define SSH_VNIC_MEDIUM               NdisMedium802_3 
#define SSH_VNIC_INITIAL_MEDIA_STATE  NdisMediaStateDisconnected

#define SSH_VNIC_LINK_SPEED           100000000
#define SSH_VNIC_BUFFER_SPACE         MAXIMUM_ETHERNET_PACKET_SIZE
#define SSH_VNIC_VENDOR_DESCRIPTOR    "INSIDE Secure QuickSec Virtual Adapter"
#define SSH_VNIC_DRIVER_VERSION       0x0101
#define SSH_VNIC_MAC_OPTIONS          (NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | \
                                       NDIS_MAC_OPTION_TRANSFERS_NOT_PEND )

/* MAXIMUM_SEND_PACKETS should be one, if we only have MiniportSend */
#define SSH_VNIC_MAXIMUM_SEND_PACKETS     1
#define SSH_VNIC_MAX_MULTICAST_ADDRESSES  32

/* NdisSetAttributesEx() parameters */
#define SSH_VNIC_CHECK_FOR_HANG_TIME_IN_SECONDS 60

#define SSH_VNIC_MINIPORT_FLAGS       (NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND | \
                                       NDIS_ATTRIBUTE_DESERIALIZE)

#define SSH_VNIC_ADAPTER_TYPE 0

#define SSH_MEM_BLOCK_HAS_BEEN_FREED 0xFFFFFFFF

#define SSH_VNIC_IS_ENABLED(vnic) \
  ((vnic->connect_status == NdisMediaStateConnected) ? TRUE : FALSE)

#pragma inline_depth(2)


/* Data structures */

typedef UCHAR EthernetAddress[ETH_LENGTH_OF_ADDRESS];

typedef struct {

  /* A handle identifying the miniport's NIC.
     The value is assigned by the NDIS library and passed
     as parameter to MiniportInitialize */
  NDIS_HANDLE miniport_handle;

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
  TRANSPORT_HEADER_OFFSET tcp_header_offset;

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
} SshVnicRec, *SshVnic;


/* Data structure to be used as a context for a "MiniportTransferData" */ 
typedef struct SshTransferDataContextRec
{
  /* Transfer data buffer. Contains the _data_ portion of the packet
     we're sending.  */
  unsigned char * data;
  unsigned int data_len;
} SshTransferDataContextStruct, * SshTransferDataContext;


/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/* this enumerates current vnics. id is used as part of mac
   address of the adapter */
static ULONG global_adapter_id = 0;

static ULONG adapter_instances = 0;

/*-------------------------------------------------------------------------
  CONSTANTS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

/*---------- MINIPORT INTERFACE ----------*/ 
/* "MiniportInitialize" */ 
NDIS_STATUS 
ssh_vnic_initialize(PNDIS_STATUS open_error_status,
                    PUINT selected_medium_index,
                    PNDIS_MEDIUM medium_array,
                    UINT medium_array_size,
                    NDIS_HANDLE miniport_handle,
                    NDIS_HANDLE wrapper_context);

/* "MiniportQueryInformation" */ 
NDIS_STATUS 
ssh_vnic_query_information(SshVnic vnic,
                           NDIS_OID oid,
                           PVOID information_buffer,
                           ULONG information_buffer_length,
                           PULONG bytes_written,
                           PULONG bytes_needed);

/* "MiniportSetInformation" */ 
NDIS_STATUS 
ssh_vnic_set_information(SshVnic vnic,
                         NDIS_OID oid,
                         PVOID information_buffer,
                         ULONG information_buffer_length,
                         PULONG bytes_read,
                         PULONG bytes_needed);

/* "MiniportSend" */ 
NDIS_STATUS 
ssh_vnic_send(SshVnic vnic,
              PNDIS_PACKET packet,
              UINT flags);

/* "MiniportTransferData" */ 
NDIS_STATUS 
ssh_vnic_transfer_data(PNDIS_PACKET packet,
                       PUINT bytes_transferred,
                       SshVnic vnic,
                       NDIS_HANDLE miniport_receive_context,
                       UINT byte_offset,
                       UINT bytes_to_transfer);

/* "MiniportCheckForHang" */ 
BOOLEAN
ssh_vnic_check_for_hang(SshVnic vnic);

/* "MiniportReset" */ 
NDIS_STATUS 
ssh_vnic_reset(PBOOLEAN addressing_reset,
               SshVnic vnict);

/* "MiniportShutdown" */ 
VOID
ssh_vnic_shutdown(PVOID shutdown_context);

/* "MiniportHalt" */ 
VOID 
ssh_vnic_halt(SshVnic vnic);

/*---------- Private interface for SSH Packet Interceptor ----------*/ 
static BOOLEAN 
ssh_vnic_icept_connect(SshVnic vnic, 
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

static NDIS_STATUS
ssh_vnic_copy_in(PVOID source, 
                 ULONG source_len,
                 PVOID sink,
                 ULONG sink_len,
                 PLONG bytes_read,
                 PLONG bytes_needed);

static NDIS_STATUS
ssh_vnic_copy_out(PVOID source, 
                  ULONG source_len,
                  PVOID sink,
                  ULONG sink_len,
                  PULONG bytes_written,
                  PULONG bytes_needed);

static NDIS_STATUS
ssh_vnic_ndis_packet_flatten(unsigned char *buffer, 
                             UINT buffer_size,
                             PNDIS_PACKET ndis_packet);

static void * 
ssh_vnic_alloc(ULONG size);

static void
ssh_vnic_free(void * ptr);

/*-------------------------------------------------------------------------
  DriverEntry()

  Every NIC miniport driver must provide a function called DriverEntry. 
  DriverEntry is called by the system to load the driver. DriverEntry 
  creates an association between the miniport NIC driver and the NDIS 
  library,  and registers the miniport's version number and entry points 
  with NDIS.

  DriverEntry registers driver's entry points to NDIS by filling
  NDIS_MINIPORT_CHARACTERISTICS structure and calling 
  NdisMRegisterMiniport.

  Arguments:
    argument1, argument2 - opaque, system specific arguments to be delivered 
                           to NdisMInitializeWrapper.

  Returns:
    Return value of NdisMRegisterMiniport.
  -------------------------------------------------------------------------*/
#pragma NDIS_INIT_FUNCTION(DriverEntry) 
NDIS_STATUS 
DriverEntry(PVOID argument1,
            PVOID argument2)
{
  DEBUGFUNC("DriverEntry");
  
  NDIS_STATUS rv;
  NDIS_MINIPORT_CHARACTERISTICS mchars;
  NDIS_HANDLE wrapper_handle;

  TRACELOG;

  /* register the miniport with NDIS */ 
  NdisMInitializeWrapper(&wrapper_handle, argument1, argument2, NULL);

  NdisZeroMemory(&mchars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

  /* initialize miniport characteristics */  
  mchars.MajorNdisVersion = SSH_VNIC_NDIS_MAJOR_VERSION;
  mchars.MinorNdisVersion = SSH_VNIC_NDIS_MINOR_VERSION;

  DEBUGSTR2(("sshvnic::DriverEntry: NdisVersion %d.%d\n", 
             mchars.MajorNdisVersion, mchars.MinorNdisVersion));

  /* Because we have cleared the whole ..._CHARACTERISTICS structure with
     NdisZeroMemory, we need to specify only the functions we actually
     implement. */ 
  mchars.CheckForHangHandler = ssh_vnic_check_for_hang;
  mchars.HaltHandler = ssh_vnic_halt;
  mchars.InitializeHandler = ssh_vnic_initialize;
  mchars.QueryInformationHandler = ssh_vnic_query_information;
  mchars.ResetHandler = ssh_vnic_reset;
  mchars.SendHandler = ssh_vnic_send; 
  mchars.SetInformationHandler = ssh_vnic_set_information;
  mchars.TransferDataHandler = ssh_vnic_transfer_data;

  rv = NdisMRegisterMiniport(wrapper_handle, &mchars, sizeof(mchars)); 

  if (rv != NDIS_STATUS_SUCCESS) 
    {
#pragma warning(disable : 6309 6387)
      NdisTerminateWrapper(wrapper_handle, NULL);
#pragma warning(default : 6309 6387)
      DEBUGSTR(("NdisMRegisterMiniport() = 0x%08x)\n", rv));
    }

  return rv;
}


/*---------- NDIS Miniport Interface ----------*/ 

/*-------------------------------------------------------------------------
  ssh_vnic_initialize()

  "MiniportInitialize" function. Initializes a new instance of SSH IPsec
  virtual NIC.

  Arguments:
    open_error_status - (not used in our implementation)
    selected_medium_index - points to a variable in which ssh_vnic_initialize 
                            sets the index of the MediumArray element that 
                            specifies the medium type the driver or its NIC 
                            uses.
    medium_array - specifies an array of NdisMediumXxx values from which 
                   ssh_vnic_initialize() selects the one that its NIC 
                   supports.
    medium_array_size - specifies the number of elements at medium_array.
    miniport_handle - specifies a handle identifying the miniport's NIC, 
                      which is assigned by the NDIS library.
    wrapper_context - (not used in our implementation)
 
  Return value:
    NDIS_STATUS_SUCCESS - new virtual NIC instance successfully initialized.
    NDIS_STATUS_UNSUPPORTED_MEDIA - the values at medium_array did not 
                                    include a medium we can support.
    NDIS_STATUS_FAILURE - could not set up a new virtual NIC.    
  -------------------------------------------------------------------------*/
#pragma NDIS_PAGABLE_FUNCTION(ssh_vnic_initialize)

NDIS_STATUS 
ssh_vnic_initialize(PNDIS_STATUS open_error_status,
                    PUINT selected_medium_index,
                    PNDIS_MEDIUM medium_array,
                    UINT medium_array_size,
                    NDIS_HANDLE miniport_handle,
                    NDIS_HANDLE wrapper_context)
{
  UINT i = 0;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  SshVnic vnic = NULL;

  DEBUGFUNC("ssh_vnic_initialize");

  PAGED_CODE();

  TRACELOG;

  *selected_medium_index = medium_array_size;

  /* look for correct medium type */
 
  for (i = 0; i < medium_array_size; i++)
    { 
      if (medium_array[i] == SSH_VNIC_MEDIUM) 
        {
          *selected_medium_index = i;
          break;
        }
    }

  if (i == medium_array_size)
    {
      DEBUGSTR(("Media type not found.\n"));
      return NDIS_STATUS_UNSUPPORTED_MEDIA;
    }

  /* Limit the amount of instances we create */ 
  if (adapter_instances >= (SSH_MAX_VNIC_INSTANCES - 1))
    {
      return NDIS_STATUS_FAILURE;
    }

  /* initialize adapter data structure */
  vnic = ssh_vnic_alloc(sizeof(*vnic));

  if (vnic == NULL) 
    {
      status = NDIS_STATUS_FAILURE;
      DEBUGSTR("Memory allocation failed!\n");
      return status;
    }

  NdisZeroMemory(vnic, sizeof(*vnic));

  vnic->miniport_handle = miniport_handle;

  /* initial status is disconnected - changed by a custom oid */
  vnic->connect_status = SSH_VNIC_INITIAL_MEDIA_STATE;

  /* Because "MiniportInitialize" is called in the context of a system 
     thread it should be totally safe to use global_adapter_id without 
     any protection. */ 
  global_adapter_id++;

  /* Make "unique" MAC address. Generated ehthernet address has format 
     02-00-00-00-XX-XX, where XX-XX is the global_adapter_id in native
     byte order */
  vnic->mac_address[0] = 2; /* set U/L bit up */
  NdisMoveMemory(&vnic->mac_address[4],
                 &((USHORT)global_adapter_id), sizeof(USHORT));

  NdisAllocateSpinLock(&vnic->lock);
  NdisAllocateSpinLock(&vnic->icept_if_lock);

  adapter_instances++;

  /* Initialize our own private interface structure, which will be 
     exposed to the interceptor */ 
  vnic->own_if.signature = SSH_ICEPT_VNIC_SIGNATURE;
  vnic->own_if.version   = SSH_ICEPT_VNIC_IF_VERSION_1;
  vnic->own_if.size = sizeof(vnic->own_if);
  vnic->own_if.cb_context = vnic;
  vnic->own_if.connect_cb = ssh_vnic_icept_connect;
  vnic->own_if.disconnect_cb = ssh_vnic_icept_disconnect;
  vnic->own_if.enable_cb = ssh_vnic_enable;
  vnic->own_if.disable_cb = ssh_vnic_disable;
  vnic->own_if.configure_cb = ssh_vnic_configure;
  vnic->own_if.receive_cb = ssh_vnic_receive;

  NdisMSetAttributesEx(miniport_handle, (NDIS_HANDLE)vnic,
                       SSH_VNIC_CHECK_FOR_HANG_TIME_IN_SECONDS,
                       SSH_VNIC_MINIPORT_FLAGS, SSH_VNIC_ADAPTER_TYPE);

  NdisMRegisterAdapterShutdownHandler(miniport_handle, vnic, 
                                      ssh_vnic_shutdown);

  return status;
}


/*-------------------------------------------------------------------------
  ssh_vnic_query information()

  Required function that returns information about the capabilities and 
  status of the virtual NIC.

  Arguments:
    vnic - points to virtual adapter context structure.
    oid - object identifier specifying the operation to be carried out.
    information_buffer - points to a buffer in which the OID-specific
                         information is to be returned.
    buffer_length - specifies the number of bytes at information_buffer.
    bytes_written - points to a variable that ssh_vnic_query_information()
                    sets to the number of bytes it is returning at
                    information_buffer.
    bytes_needed - points to a variable that ssh_vnic_query_information()
                   sets to the number of additional bytes it needs to
                   satisfy the request if buffer_length is less than OID 
                   requires.
  Returns:
    NDIS_STATUS_SUCCESS or NDIS_STATUS_XXX error code specifying the
    error occurred. See DDK documentation for details.
  -------------------------------------------------------------------------*/
NDIS_STATUS 
ssh_vnic_query_information(SshVnic vnic,
                           NDIS_OID oid,
                           PVOID information_buffer,
                           ULONG information_buffer_length,
                           PULONG bytes_written,
                           PULONG bytes_needed)
{
#define SSH_VNIC_COPY_OUT(buf,size)                \
      ssh_vnic_copy_out((PVOID)(buf),              \
                        (size),                    \
                        information_buffer,        \
                        information_buffer_length, \
                        bytes_written,             \
                        bytes_needed)

  DEBUGFUNC("ssh_vnic_query_information");

  static const NDIS_OID  ssh_vnic_supported_oids[] = 
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
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_PROTOCOL_OPTIONS,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_NETWORK_LAYER_ADDRESSES,
    OID_GEN_TRANSPORT_HEADER_OFFSET,

    /* General Statistics Objects */
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_NO_BUFFER,

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

    /* Custom OID's */
    OID_SSH_QUERY_INTERFACE
  };

  NDIS_STATUS status;
  ULONG ulong_value=0; /* unsigned long for general use */

  ASSERT((information_buffer_length > 0 && information_buffer != NULL) || 
         (information_buffer_length == 0));

  /* initialize return values to something legal */
  *bytes_written = 0;
  *bytes_needed = 0;

  switch (oid) 
    {
    /* General Operational Characteristics */

    case OID_GEN_SUPPORTED_LIST:
      return SSH_VNIC_COPY_OUT(ssh_vnic_supported_oids, 
                          sizeof(ssh_vnic_supported_oids));

    case OID_GEN_HARDWARE_STATUS: 
      {
        NDIS_HARDWARE_STATUS hw_status;

        if (SSH_VNIC_IS_ENABLED(vnic))
          hw_status = NdisHardwareStatusReady;
        else
          hw_status = NdisHardwareStatusNotReady;

        return SSH_VNIC_COPY_OUT(&hw_status, sizeof(hw_status));
      }

    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE: 
      {
        NDIS_MEDIUM medium = SSH_VNIC_MEDIUM;

        return SSH_VNIC_COPY_OUT(&medium, sizeof(medium));
      }

    case OID_GEN_MAXIMUM_LOOKAHEAD:
    case OID_GEN_MAXIMUM_FRAME_SIZE:
    case OID_GEN_CURRENT_LOOKAHEAD:
      ulong_value = MAXIMUM_ETHERNET_PACKET_SIZE - ETHERNET_HEADER_SIZE;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_LINK_SPEED:
      ulong_value = SSH_VNIC_LINK_SPEED;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      ulong_value = SSH_VNIC_BUFFER_SPACE;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      ulong_value = MAXIMUM_ETHERNET_PACKET_SIZE;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_VENDOR_ID:
      ulong_value = 0xFFFFFF; /* three-byte IEEE-registered vendor code */
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_VENDOR_DESCRIPTION:
      {
        char vendor[] = SSH_VNIC_VENDOR_DESCRIPTOR;

        return SSH_VNIC_COPY_OUT(vendor, (ULONG)strlen(vendor)+1);
      }

    case OID_GEN_VENDOR_DRIVER_VERSION:
      {
        USHORT version = SSH_VNIC_DRIVER_VERSION;

        return SSH_VNIC_COPY_OUT(&version, sizeof(version));
      }

    case OID_GEN_CURRENT_PACKET_FILTER:
      ulong_value = vnic->packet_filter;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_DRIVER_VERSION: 
      { 
        USHORT version = (SSH_VNIC_NDIS_MAJOR_VERSION << 8) | 
                          SSH_VNIC_NDIS_MINOR_VERSION; 

        return SSH_VNIC_COPY_OUT(&version, sizeof(version));
      }

    case OID_GEN_MAC_OPTIONS:
      ulong_value = SSH_VNIC_MAC_OPTIONS;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_MEDIA_CONNECT_STATUS:
      {
        NDIS_MEDIA_STATE conn_status = vnic->connect_status;

        return SSH_VNIC_COPY_OUT(&conn_status, sizeof(conn_status));
      }

    case OID_GEN_MAXIMUM_SEND_PACKETS:
      ulong_value = SSH_VNIC_MAXIMUM_SEND_PACKETS;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

    case OID_GEN_SUPPORTED_GUIDS: /* optional */
    case OID_GEN_PHYSICAL_MEDIUM: /* optional */
      return NDIS_STATUS_NOT_SUPPORTED;

      /* General Statistics */
    case OID_GEN_XMIT_OK:
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->good_transmits;
          status = SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
          if (status == NDIS_STATUS_SUCCESS)
            *bytes_needed = sizeof(vnic->good_transmits);
          return status;
        }
      /* Return 64-bit value */
      return SSH_VNIC_COPY_OUT(&vnic->good_transmits, 
                               sizeof(vnic->good_transmits));

    case OID_GEN_RCV_OK:
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->good_receives;
          status = SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
          if (status == NDIS_STATUS_SUCCESS)
            *bytes_needed = sizeof(vnic->good_receives);
          return status;
        }
      /* Return 64-bit value */
      return SSH_VNIC_COPY_OUT(&vnic->good_receives,
                               sizeof(vnic->good_receives));

    case OID_GEN_XMIT_ERROR:
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_transmits;
          return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
          if (status == NDIS_STATUS_SUCCESS)
            *bytes_needed = sizeof(vnic->bad_transmits);
          return status;
        }
      /* Return 64-bit value */
      return SSH_VNIC_COPY_OUT(&vnic->bad_transmits,
                               sizeof(vnic->bad_transmits));

    case OID_GEN_RCV_ERROR:
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_receives;
          status = SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
          if (status == NDIS_STATUS_SUCCESS)
            *bytes_needed = sizeof(vnic->bad_receives);
          return status;
        }
      /* Return 64-bit value */
      return SSH_VNIC_COPY_OUT(&vnic->bad_receives,
                               sizeof(vnic->bad_receives));

    case OID_GEN_RCV_NO_BUFFER:
      if (information_buffer_length == sizeof(ulong_value))
        {
          /* Return 32-bit value */
          ulong_value = (ULONG)vnic->bad_receives_no_buffer;
          status = SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
          if (status == NDIS_STATUS_SUCCESS)
            *bytes_needed = sizeof(vnic->bad_receives_no_buffer);
          return status;
        }
      /* Return 64-bit value */
      return SSH_VNIC_COPY_OUT(&vnic->bad_receives_no_buffer,
                               sizeof(vnic->bad_receives_no_buffer));

    case OID_GEN_DIRECTED_BYTES_XMIT: /* optional oids - not supported*/
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
      return SSH_VNIC_COPY_OUT(vnic->mac_address,
                               sizeof(vnic->mac_address));

    case OID_802_3_MULTICAST_LIST:
      return SSH_VNIC_COPY_OUT(vnic->multicast_addresses, 
               sizeof(EthernetAddress) * vnic->nbr_of_mc_addresses);

    case OID_802_3_MAXIMUM_LIST_SIZE:
      ulong_value = SSH_VNIC_MAX_MULTICAST_ADDRESSES;
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));
  
    case OID_802_3_MAC_OPTIONS: /* optional */
      ulong_value = 0; /* we could emulate some MAC options ...*/
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

      /* mandatory statistical oids */ 
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
      ulong_value = 0; /* no faults in the virtual world... */
      return SSH_VNIC_COPY_OUT(&ulong_value, sizeof(ulong_value));

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
      {
        /* Because we have specified NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND
           (at initialisation) we have to succeed OID_PNP_CAPABILITIES 
           request and return 'NdisDeviceStateUnspecified' as wake up 
           capabilities. */  

        static const NDIS_PNP_CAPABILITIES ssh_vnic_pnp_capabilities = 
          { 
            NDIS_DEVICE_WAKE_UP_ENABLE,
            {NdisDeviceStateUnspecified,
             NdisDeviceStateUnspecified,
             NdisDeviceStateUnspecified}
          };

        return SSH_VNIC_COPY_OUT(&ssh_vnic_pnp_capabilities,
                            sizeof(ssh_vnic_pnp_capabilities));
      }

    case OID_PNP_QUERY_POWER:
      /* we are ready to change to any power mode at any time */
      *bytes_written = 0;
      return NDIS_STATUS_SUCCESS;

    case OID_PNP_WAKE_UP_PATTERN_LIST:
    case OID_PNP_ENABLE_WAKE_UP:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* statistical oids, both are optional */
    case OID_PNP_WAKE_UP_ERROR:
    case OID_PNP_WAKE_UP_OK:
      return NDIS_STATUS_NOT_SUPPORTED;

      /* Task Offload Objects */
    case OID_TCP_TASK_OFFLOAD: 
      {
        PNDIS_TASK_OFFLOAD_HEADER ptoh = 
          (PNDIS_TASK_OFFLOAD_HEADER)information_buffer;

        if (information_buffer_length < sizeof(NDIS_TASK_OFFLOAD_HEADER))
          {
            *bytes_needed = sizeof(NDIS_TASK_OFFLOAD_HEADER);
            return NDIS_STATUS_BUFFER_TOO_SHORT;
          } 
        else 
          {
            /* NDIS provides us NDIS_TASK_OFFLOAD_HEADER into
               which we should fill our offload capabilities.
               We do not support any, so just set OffsetFirstTask field
               to zero (meaning no task offload capabilities) */
            ptoh->OffsetFirstTask = 0;
            *bytes_written = sizeof(NDIS_TASK_OFFLOAD_HEADER);
            return NDIS_STATUS_SUCCESS;
          }
      }

      /* custom oid */
    case OID_SSH_QUERY_INTERFACE:
      /* copy of the private interface record */
      return SSH_VNIC_COPY_OUT(&vnic->own_if, sizeof(vnic->own_if));

    } /* switch (oid) */

  return NDIS_STATUS_INVALID_OID;

#undef SSH_VNIC_COPY_OUT

}


/*-------------------------------------------------------------------------
  ssh_vnic_set_information()

  Required function that allows bound protocol drivers (or NDIS) to request 
  changes in the state information that the miniport maintains for particular
  OIDs.

  Arguments:
    vnic - points to virtual adapter context structure
    oid - object identifier specifying the set operation to be carried out. 
    information_buffer - points to a buffer containing OID-specific data
    information_buffer_length - specifies the number of bytes at 
                                information_buffer. 
    bytes_read - points to a variable to be set to the number of bytes
                 ssh_vnic_set_information() read.
    bytes_needed - points to a variable to be set to the number of additional
                   bytes ssh_vnic_set_information() needs to satisfy the
                   request if information_buffer_lenght is less than OID
                   requires. 

  Returns:
    NDIS_STATUS_SUCCESS or NDIS_STATUS_XXX error code specifying the
    error occurred. See DDK documentation for details.
  -------------------------------------------------------------------------*/
NDIS_STATUS 
ssh_vnic_set_information(SshVnic vnic,
                         NDIS_OID oid,
                         PVOID information_buffer,
                         ULONG buffer_length,
                         PULONG bytes_read,
                         PULONG bytes_needed)
{
#define SSH_COPY_IN(data_ptr, size)  \
  ssh_vnic_copy_in(information_buffer, buffer_length, \
                   (void *)data_ptr, (size), bytes_read, bytes_needed)

  DEBUGFUNC("ssh_vnic_set_information");

  TRACELOG;





  ASSERT((buffer_length > 0 && information_buffer != NULL) || 
         (buffer_length == 0));

  *bytes_read = *bytes_needed = 0;

  switch (oid) 
    {
      /* General Objects */
    case OID_GEN_CURRENT_PACKET_FILTER:
      return SSH_COPY_IN(&vnic->packet_filter, sizeof(vnic->packet_filter));

    case OID_GEN_CURRENT_LOOKAHEAD:
      return SSH_COPY_IN(&vnic->lookahead_size, sizeof(vnic->lookahead_size));

    case OID_GEN_PROTOCOL_OPTIONS:
      return SSH_COPY_IN(&vnic->protocol_options, 
                         sizeof(vnic->protocol_options));

    case OID_GEN_NETWORK_LAYER_ADDRESSES:
      return NDIS_STATUS_SUCCESS;

    case OID_GEN_TRANSPORT_HEADER_OFFSET: 
      {
        PTRANSPORT_HEADER_OFFSET ptho = 
          (PTRANSPORT_HEADER_OFFSET)information_buffer;

        if (buffer_length < sizeof(PTRANSPORT_HEADER_OFFSET))
          /* we got invalid strucutre */
          return NDIS_STATUS_INVALID_LENGTH;

        if (ptho == NULL)
          return NDIS_STATUS_INVALID_DATA;

        if (ptho->ProtocolType == NDIS_PROTOCOL_ID_TCP_IP) 
          {
            /* we are mainly interested in tcp/ip */
            return ssh_vnic_copy_in(ptho, sizeof(*ptho),
                                    &vnic->tcp_header_offset, 
                                    sizeof(vnic->tcp_header_offset),
                                    bytes_read, bytes_needed);
          } 
        else
          {
            return NDIS_STATUS_SUCCESS;
          }
      } 

      /* Ethernet Objects */

    case OID_802_3_MULTICAST_LIST:
      /* copy in the multicast list */
      if (buffer_length % sizeof(EthernetAddress) != 0)
        /* not ethernet addresses */
        return NDIS_STATUS_INVALID_LENGTH;

      if (buffer_length / sizeof(EthernetAddress) > 
                                            SSH_VNIC_MAX_MULTICAST_ADDRESSES)
        /* too much stuff for us */
        return NDIS_STATUS_INVALID_LENGTH;
      
      NdisMoveMemory(vnic->multicast_addresses, information_buffer, 
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
      return NDIS_STATUS_SUCCESS;
      
      /* Task Offload Objects */ 
    case OID_TCP_TASK_OFFLOAD:
    case OID_TCP_TASK_IPSEC_ADD_SA:
    case OID_TCP_TASK_IPSEC_DELETE_SA:
      return NDIS_STATUS_NOT_SUPPORTED;
    }  /* switch (oid) */
 
  return NDIS_STATUS_INVALID_OID;

#undef SSH_COPY_IN
}


/*-------------------------------------------------------------------------
  ssh_vnic_send()

  MiniportSend function. MiniportSend transfers a protocol-supplied 
  packet over the network.

  VNIC forward packet to the interceptor (and further to
  the engine) by calling send callback function. The function
  pointer is received from the interceptor at time when
  connection between interceptor and vnic is established.

  Because the traffic is intercepted, only DHCP and ARP packets
  should reach the MiniportSend.

  Arguments: 
    vnic - points to virtual adapter context structure.
    packet - points to a packet descriptor specifying the data to be 
             transmitted.
    flags - optional packet flags, set by the protocol.

  Returns:
    NDIS_STATUS_SUCCESS - packet successfully sent
    NDIS_STATUS_FAILURE - some error occurred.
  -------------------------------------------------------------------------*/
NDIS_STATUS 
ssh_vnic_send(SshVnic vnic,
              PNDIS_PACKET ndis_packet,
              UINT flags)
{
  NDIS_STATUS rv = NDIS_STATUS_FAILURE;
  UINT flat_packet_len;
  PCHAR flat_packet;

  DEBUGFUNC("ssh_vnic_send");

  TRACELOG;

  NdisQueryPacket(ndis_packet, NULL, NULL, NULL, &flat_packet_len);

  /* copy packet into a private buffer */
  flat_packet = ssh_vnic_alloc(flat_packet_len);

  if (flat_packet)
    {
      rv = ssh_vnic_ndis_packet_flatten(flat_packet, flat_packet_len, 
                                        ndis_packet);

      if (rv == NDIS_STATUS_SUCCESS)
        {
          SshIceptDrvIf icept_if;

          /* If we are in "promiscuous mode", we should also loopback the 
             packet, otherwice network monitoring tools don't see our 
             "sends"... */ 
          if (vnic->packet_filter & NDIS_PACKET_TYPE_PROMISCUOUS)
            {
              ssh_vnic_receive(vnic, flat_packet, flat_packet_len);
            }
  
          icept_if = ssh_vnic_interceptor_if_get(vnic, FALSE);

          if (icept_if != NULL)
            {
              /* Execute interceptor's send callback */ 
              rv = (*icept_if->send_cb)(icept_if->cb_context,
                                        flat_packet, flat_packet_len);

              (*icept_if->release_cb)(icept_if->cb_context);
            }
        }

      /* Free packet copy */
      ssh_vnic_free(flat_packet);
    }
  else  
    {
      DEBUGSTR(("Memory allocation failed!\n", rv));
    }

  if (rv == NDIS_STATUS_SUCCESS) /* NDIS_STATUS_PENDING is not possible */
    vnic->good_transmits++;
  else
    vnic->bad_transmits++;

  DEBUGSTR2(("ssh_vnic_send returns (Status = 0x%08x)\n", rv));

  return rv;
}


/*-------------------------------------------------------------------------
  ssh_vnic_transfer_data()

  Copies the contents of the received packet to a given protocol-allocated
  packet.

  Arguments:
    packet - points to a packet descriptor with chained buffers into which
             the data should be copied.
    bytes_transferred - points to a variable that ssh_vnic_transfer_data()
                        will set to the number of bytes it copied.
    vnic - points to virtual NIC context structure.
    receive_ctx - points to virtual NIC specific "transfer data context".
    byte_offset - specifies the offset within the received packet at which
                  ssh_vnic_transfer_data() should begin the copy.
    bytes_to_transfer - specifies how many bytes to copy.

  Returns:
    NDIS_STATUS_SUCCESS - packet successfully copied.
    NDIS_STATUS_FAILURE - some error occurred.
  -------------------------------------------------------------------------*/
NDIS_STATUS 
ssh_vnic_transfer_data(PNDIS_PACKET packet,
                       PUINT bytes_transferred,
                       SshVnic vnic,
                       SshTransferDataContext receive_ctx,
                       UINT byte_offset,
                       UINT bytes_to_transfer)
{
  PNDIS_BUFFER dest;
  UINT buf_count, i;
  UINT ofs, len;
  PVOID vaddr;

  DEBUGFUNC("ssh_vnic_transfer_data");

  if ((byte_offset + bytes_to_transfer) > receive_ctx->data_len)
    goto failure;

  /* Get the packet. Calling protocol has to provide big enough packet,
     so no need to worry about that. */
  NdisQueryPacket(packet, NULL, &buf_count, &dest, NULL);

  *bytes_transferred = 0;

  /* Copy data to buffers */
  for (i = 0, ofs = 0; i < buf_count && bytes_to_transfer; i++)
    {
      NdisQueryBufferSafe(dest, &vaddr, &len, LowPagePriority); 

      if (vaddr == NULL)
        goto failure;

      if (ofs < byte_offset)
        {
          ofs += len;

          if (byte_offset < ofs)
            {
              len = ofs - byte_offset;
              ofs = byte_offset;
            }
          else
            {
              /* Jump to next buffer. */
              NdisGetNextBuffer(dest, &dest);
              continue;
            }
        }

      if (len >= bytes_to_transfer)
        {
          if (len > bytes_to_transfer)
            len = bytes_to_transfer;

          NdisMoveMemory(vaddr, receive_ctx->data + ofs, len);
          bytes_to_transfer -= len;
          ofs += len;

          *bytes_transferred += len;
        }
      else
        {
          goto failure;
        }

      /* Jump to next buffer. */
      NdisGetNextBuffer(dest, &dest);
    }
   
  return NDIS_STATUS_SUCCESS;

 failure:

  *bytes_transferred = 0;
  return NDIS_STATUS_FAILURE;
}


/*-------------------------------------------------------------------------
  ssh_vnic_check_for_hang()

  "Checks" the internal state of NIC. Returns always FALSE indicating that
  the virtual NIC is up and running (no "hardware hangs").

  Arguments:
    vnic - points to virtual NIC context structure.

  Returns:
    FALSE
  -------------------------------------------------------------------------*/
BOOLEAN
ssh_vnic_check_for_hang(SshVnic vnic)
{
  DEBUGFUNC("ssh_vnic_check_for_hang");

  TRACELOG;

  return FALSE; /* this hw never hangs! */ 
}


/*-------------------------------------------------------------------------
  ssh_vnic_reset()

  This function issues a "hardware reset" to virtual NIC.

  Arguments:
    addressing_reset - points to a variable that ssh_vnic_reset() always sets
                       to FALSE (meaning that the NDIS library doesn't need
                       to restore addressing information).
    vnic - points to virtual NIC context structure.

  Returns:
    NDIS_STATUS_SUCCESS.
  -------------------------------------------------------------------------*/
NDIS_STATUS 
ssh_vnic_reset(PBOOLEAN addressing_reset,
               SshVnic vnic)
{
  DEBUGFUNC("sshvnic_reset");

  TRACELOG;

  if (addressing_reset != NULL)
    *addressing_reset = FALSE;

  return NDIS_STATUS_SUCCESS;
}


/*-------------------------------------------------------------------------
  ssh_vnic_halt()

  This function is called by NDIS when SSH virtual NIC is removed or
  disabled.

  Arguments:
    vnic - points to virtual NIC context structure.
  -------------------------------------------------------------------------*/
#pragma NDIS_PAGABLE_FUNCTION(ssh_vnic_halt)

VOID 
ssh_vnic_halt(SshVnic vnic)
{
  DEBUGFUNC("ssh_vnic_halt");

  PAGED_CODE();

  TRACELOG;

  NdisMDeregisterAdapterShutdownHandler(vnic->miniport_handle);

  NdisFreeSpinLock(&vnic->icept_if_lock);
  NdisFreeSpinLock(&vnic->lock);

  /* free adapter object */
  ssh_vnic_free(vnic);

  adapter_instances--;
}


/*-------------------------------------------------------------------------
  ssh_vnic_shutdown()

  Function which will bw called when the system is shut down. Currently 
  our implementation does nothing.

  Arguments:
    vnic - pointer to virtual NIC context.
  -------------------------------------------------------------------------*/
VOID
ssh_vnic_shutdown(SshVnic vnic)
{
  DEBUGFUNC("ssh_vnic_shutdown_handler");

  TRACELOG;
}


/*---------- Private Interface For SSH Packet Interceptor ----------*/ 

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
  ssh_vnic_switch_connect_status(vnic, NdisMediaStateConnected); 

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
  ssh_vnic_switch_connect_status(vnic, NdisMediaStateDisconnected);
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
                 unsigned char * buffer,
                 unsigned int buffer_len)
{
  SshTransferDataContextStruct ctx;

  ctx.data = buffer + ETHERNET_HEADER_SIZE;
  ctx.data_len = buffer_len - ETHERNET_HEADER_SIZE;

  NdisMEthIndicateReceive(vnic->miniport_handle, &ctx,
                          buffer, ETHERNET_HEADER_SIZE,
                          ctx.data, ctx.data_len, ctx.data_len);

  /* Traffic here is so low that we can complete after each packet */
  NdisMEthIndicateReceiveComplete(vnic->miniport_handle);

  vnic->good_receives++;
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
  NDIS_MEDIA_STATE  old_state;

  DEBUGFUNC("ssh_vnic_switch_media_state");

  ASSERT(new_state == NdisMediaStateConnected || 
         new_state == NdisMediaStateDisconnected);

  old_state = vnic->connect_status;

  if (new_state == old_state) 
    {
      /* nothing to change */
      return NDIS_STATUS_SUCCESS;
    }
 
  if ((new_state == NdisMediaStateConnected) ||
      (new_state == NdisMediaStateDisconnected))
    {
      vnic->connect_status = new_state;

#pragma warning(disable : 6309 6387)
      if (vnic->connect_status == NdisMediaStateConnected)
        {
          NdisMIndicateStatus(vnic->miniport_handle, 
                              NDIS_STATUS_MEDIA_CONNECT, NULL, 0);
        }
      else
        {
          NdisMIndicateStatus(vnic->miniport_handle, 
                              NDIS_STATUS_MEDIA_DISCONNECT, NULL, 0);
        } 
#pragma warning(default : 6309 6387)

      NdisMIndicateStatusComplete(vnic->miniport_handle);

      return NDIS_STATUS_SUCCESS;
    }
  else
    {
      return NDIS_STATUS_INVALID_DATA;
    }
}


/*--------------------------------------------------------------------------
  ssh_vnic_ndis_packet_flatten()

  Convert NDIS packet to sequential byte array.

  Arguments:
    buffer - points to a caller supplied buffer for the "flat" packet.
    buffer_size - size of buffer pointed to by 'buffer'.
    ndis_packet - points to a NDIS packet to be converted.

  Returns:
    NDIS_STATUS_SUCCESS 
    NDIS_STATUS_FAILURE
  --------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_vnic_ndis_packet_flatten(unsigned char *buffer, 
                             UINT flat_packet_max,
                             PNDIS_PACKET ndis_packet)
{
  NDIS_STATUS rv = NDIS_STATUS_SUCCESS;

  UINT buf_count = 0;             /* buffers in packet */
  UINT total_packet_length = 0;   /* total packet length */
  UINT buffer_length = 0;         /* buffer length */
  PNDIS_BUFFER buffer_ptr = NULL; /* buffer pointer */
  PVOID buffer_data_ptr = NULL;   /* buffer data address */
  PCHAR packet_copy = NULL;       /* packet copy, this is where we copy 
                                     packet data */
  PCHAR packet_copy_ptr = NULL;   /* pointer to packet copy area */

  NdisQueryPacket(ndis_packet, NULL, &buf_count, &buffer_ptr, 
                  &total_packet_length);

  if (flat_packet_max < total_packet_length)
    {
      rv = NDIS_STATUS_FAILURE;
      goto End;
    }

  packet_copy = buffer;

  packet_copy_ptr = packet_copy;
  while (buf_count--) /* while we have buffers  */
    {
      if (buffer_ptr == NULL) 
        {
          rv = NDIS_STATUS_FAILURE;
          goto End;
        }

      NdisQueryBufferSafe(buffer_ptr, &buffer_data_ptr, 
                          &buffer_length, LowPagePriority);

      if (buffer_data_ptr == NULL)
        {
          rv = NDIS_STATUS_FAILURE;
          goto End;
        }

      if (buffer_length != 0)
        {
          if (buffer_data_ptr == NULL)
            {
              rv = NDIS_STATUS_FAILURE;
              goto End;
            }

          if (packet_copy_ptr+buffer_length > packet_copy+total_packet_length)
            {
              rv = NDIS_STATUS_FAILURE;
              goto End;
            }

          NdisMoveMemory(packet_copy_ptr, buffer_data_ptr, buffer_length);

          packet_copy_ptr += buffer_length;
        }     

        NdisGetNextBuffer(buffer_ptr, &buffer_ptr);

    } /* end while */

  rv = NDIS_STATUS_SUCCESS;

End:
  return rv;
}


/* --------------------------------------------------------------------
   ssh_vnic_make_ether_address()

   -------------------------------------------------------------------- */
_inline static VOID
ssh_vnic_make_ether_address(EthernetAddress adr, ULONG key)
{
  CHAR *a = (CHAR *)&key;
  
  DEBUGFUNC("ssh_vnic_make_ether_address");

  ASSERT(adr != NULL);

  adr[0] = 0xA; /* set U/L bit up */
  adr[1] = 0xB2;
  adr[2] = a[1];
  adr[3] = a[2];
  adr[4] = a[0]^0xff;
  adr[5] = a[3]^0xff;
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
#pragma warning(disable : 6011 6014)
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
#pragma warning(default : 6011 6014)


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


/*--------------------------------------------------------------------------
  INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

/* copy requested information to callers buffer in the context 
   of MiniportQueryInformation */
__inline static NDIS_STATUS
ssh_vnic_copy_out(PVOID source, 
                  ULONG source_len,
                  PVOID sink,
                  ULONG sink_len,
                  PULONG bytes_written,
                  PULONG bytes_needed)
{
  if (source_len > sink_len) 
    {
      *bytes_needed = source_len;

      return NDIS_STATUS_BUFFER_TOO_SHORT;
    } 
  else 
    {
      *bytes_needed = source_len;
      *bytes_written = source_len;

      if (source_len > 0)
        NdisMoveMemory(sink, source, source_len);

      return NDIS_STATUS_SUCCESS;
    }
}

/* copy in information from callers buffer in the context 
   of MiniportSetInformation */
__inline static NDIS_STATUS
ssh_vnic_copy_in(PVOID source, 
                 ULONG source_len,
                 PVOID sink,
                 ULONG sink_len,
                 PLONG bytes_read,
                 PLONG bytes_needed)  
{
  if (sink_len != source_len)
    {
      *bytes_needed = sink_len;

      return NDIS_STATUS_INVALID_LENGTH;
    } 
  else 
    {
      *bytes_read = source_len;

      if (source_len > 0)
        NdisMoveMemory(sink, source, source_len);

      return NDIS_STATUS_SUCCESS;
    }
}














































































































































































