/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the driver type (NDIS Intermediate vs. NDIS filter
   driver) independent type definitions and function declarations
   for SSH Adapter object.
*/

#ifndef SSH_ADAPTER_COMMON_H
#define SSH_ADAPTER_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/





/* The maximum length of SSH adapter name buffer (in bytes) */ 
#define SSH_ADAPTER_NAME_SIZE_MAX           32

/* The maximum length of network adapter media address buffer */
#ifdef NDIS_MAX_PHYS_ADDRESS_LENGTH
#define SSH_ADAPTER_MEDIA_ADDR_LEN_MAX      NDIS_MAX_PHYS_ADDRESS_LENGTH
#else
#define SSH_ADAPTER_MEDIA_ADDR_LEN_MAX      16
#endif /* NDIS_MAX_PHYS_ADDRESS_LENGTH */

/* Default values for all adapter names. These can be redefined in interceptor
   specific include file (e.g "adapter.h") */
#define SSH_ADAPTER_DEV_NAME_PREFIX         L"\\Device\\"
#define SSH_ADAPTER_DEV_NAME_PREFIX_SIZE    16
#define SSH_DEVICE_OBJ_NAME_PREFIX          L"\\Device\\"
#define SSH_DEVICE_OBJ_NAME_PREFIX_SIZE     16
/* Offset into adapter name/GUID at adapter name string */
#define SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET   8

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/* Type definitions for OID query/set requests */
typedef enum
{
  SSH_OID_REQUEST_QUERY_INFORMATION,
  SSH_OID_REQUEST_SET_INFORMATION
} SshOidRequestType;

typedef struct SshOidRequestRec
{
  LIST_ENTRY link;

  /* Type of OID request */
  SshOidRequestType type;
  NDIS_OID oid;

  /* Input/output buffer */
  void *buffer;
  SshUInt32 buffer_len;
  SshUInt32 bytes_transferred;
  SshUInt32 bytes_needed;

  /* Final status of the request */
  NDIS_STATUS status;
} SshOidRequestStruct, *SshOidRequest;


/* Adapter state. These states correspond to the module states of NDIS 6.0 
   filter driver (see Windows Vista WDK chapter "Module States of a Filter 
   Driver" for details). */
typedef enum 
{
  SSH_ADAPTER_STATE_DETACHED,
  SSH_ADAPTER_STATE_ATTACHING,
  SSH_ADAPTER_STATE_PAUSED,
  SSH_ADAPTER_STATE_RESTARTING,
  SSH_ADAPTER_STATE_RUNNING,
  SSH_ADAPTER_STATE_PAUSING,
  SSH_NUM_ADAPTER_STATES
} SshAdapterState;


/* Reason for pause. */
typedef enum
{
  /* Unspecified reason for pause */
  SSH_ADAPTER_PAUSE_REASON_UNSPECIFIED,
  /* Binding to IPv4 is being created */
  SSH_ADAPTER_PAUSE_REASON_BIND_IPV4,
  /* Binding to IPv4 is being created */
  SSH_ADAPTER_PAUSE_REASON_BIND_IPV6,
  /* Binding to unknown/unspecified protocol is being created */
  SSH_ADAPTER_PAUSE_REASON_BIND_PROTOCOL,
  /* Binding to IPv4 protocol is being removed */
  SSH_ADAPTER_PAUSE_REASON_UNBIND_IPV4,
  /* Binding to IPv6 protocol is being removed */
  SSH_ADAPTER_PAUSE_REASON_UNBIND_IPV6,
  /* Protocol binding of unknown protocol is being removed (the protocol can 
     also be either IPv4 or IPv6) */
  SSH_ADAPTER_PAUSE_REASON_UNBIND_PROTOCOL, 
  /* Adapter is going to low-power state */
  SSH_ADAPTER_PAUSE_REASON_LOW_POWER, 
  /* Interceptor binding is being added */
  SSH_ADAPTER_PAUSE_REASON_ATTACH_INTERCEPTOR,
  /* Interceptor binding is being removed */
  SSH_ADAPTER_PAUSE_REASON_DETACH_INTERCEPTOR,
  /* Protocol stack is being restarted */
  SSH_ADAPTER_PAUSE_REASON_RESTART_STACK,
} SshAdapterPauseReason;


/* Bit flags specifying which features (e.g. send, receive, OID requests etc.)
   are currently enabled for the adapter. */
typedef union SshAdapterEnableFlagsRec
{
  struct 
    {
      /* NOTE! Do not add more than 32 bit flags here unless you also
               change the code using 'all_flags' data member. */

      /* When this flag is set, the interceptor can send receive indications
         to upper layer. If this flag is cleared but 'allow_receive' set, the
         interceptor can either buffer the received data or ignore it. */
      unsigned int allow_initiate_receive_indications : 1;

      /* When this flag is set, inteceptor should accept receive indications
         from the lower layer. If the flag is cleared, all receive indications
         must be denied immediately. */
      unsigned int allow_receive : 1;

      /* When this flag is set, the interceptor can send network packets to
         lower layer driver. If this flag is cleared but 'allow_send' set, the
         interceptor can either buffer the received data or silently drop the 
         network packets. */
      unsigned int allow_initiate_send : 1;

      /* When this flag is set, the interceptor can accept network packets 
         from upper layer drivers. */
      unsigned int allow_send : 1;

      /* When this flag is set, the interceptor can provide status indications
         (e.g. with NdisMIndicateStatus/NdisFIndicateStatus). */
      unsigned int allow_initiate_status_indications : 1;

      /* When this flag is set, the interceptor should process received status
         indications. */
      unsigned int allow_status_indications : 1;

      /* When this flag is set, the interceptor can initiate OID requests. */
      unsigned int allow_initiate_oid_requests : 1;

      /* When this flag is set, the interceptor should handle OID requests
         coming from upper layer driver. */
      unsigned int allow_oid_requests : 1;     
    } flags;

  /* Same flags in one unsigned long variable, so we can use interlocked 
     functions (InterlockedExchange() etc.) for updating them all atomically
     without spin locks. */
  unsigned long all_flags;
} SshAdapterEnableFlagsStruct, *SshAdapterEnableFlags;



/*----
  Type definition for "adapter objects" that are layered between
  protocol driver (or filter dirver) and network driver. These adapter 
  objects intercept all the network I/O operations between the upper layer 
  protocol/filter and the real networking device.
  ----*/
typedef struct SshAdapterRec 
{
  /* Link entry for keeping these in a list */
  LIST_ENTRY link;

  /* Unique ID (0...N) for adapter */
  SshInterceptorIfnum ifnum;

  /* Adapter state */
  SshAdapterState state;
  LONG state_transition_pending;

  /* Bit flags specifying currently enabled features */
  SshAdapterEnableFlagsStruct enable_flags;
  /* Adapter state-specific feature flags. The flags corresponding to the
     current state must be copied to 'enable_flags' during state transtion. 
     This is done automatically as long as you use state transition functions
     (ssh_adapter_attach_common(), ssh_adapter_restart_common() etc.) located 
     in adapter_common.c */
  SshAdapterEnableFlagsStruct state_flags[SSH_NUM_ADAPTER_STATES];

  /* Interceptor specific callbacks */
  void *restart_fn;
  void *pause_fn;

  /* Globally unique ID of this adapter */
  GUID guid;

  /* The name of the underlaying real network adapter */



  NDIS_STRING orig_name;  

  /* The name appearing in the GUI, ipconfig etc. */
  char friendly_name[SSH_INTERCEPTOR_IFNAME_SIZE];

  /* The SSH name for adapter that is reported to engine/policy manager */
  unsigned char ssh_name[SSH_ADAPTER_NAME_SIZE_MAX];

  /* Handle that NDIS has reserved for us */
  NDIS_HANDLE handle;

  /* Handle for retrieving configuration information from OS registry */
  NDIS_HANDLE config_handle;

  /* The media (802.3, WAN) of our device */
  NDIS_MEDIUM media;

  /* MAC Options flag. Specifies a bitmask that defines properties
     of the underlaying device. If NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA flag
     is set we can use memcpy() or memmove() operations to access the
     received lookahead data. Otherwise we have to use "one-byte-at-a-time"
     memory access operations */
  ULONG options;

  /* Current lookahead data buffer length. The value for this attribute
     is received by intercepting OID_GEN_CURR_LOOKAHEAD set operation. 
     This value is then used to check that enough data exist in the 1st
     NDIS_PACKET buffer when indicating packets up to protocol layer */ 
  ULONG lookahead_size;

  /* Physical address and it's length */
  UCHAR media_addr[SSH_ADAPTER_MEDIA_ADDR_LEN_MAX];
  ULONG media_addr_len;

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* List for WAN interface information */
  SshKernelRWMutexStruct wan_if_lock;
  LIST_ENTRY wan_if;
  ULONG wan_if_cnt;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Event object that is used for adapter state change signalling */
  SshEvent wait_event;

  /* The status of latest asynchronous operation */
  NDIS_STATUS result;

  /* Pointer into the interceptor object */
  SshInterceptor interceptor;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  /* Pointer into the SSH virtual adapter */ 
  struct SshVirtualAdapterRec *va;

  /* Registration interface context */
  void *vnic_interface;
  SshUInt32 vnic_interface_size;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */ 

  /* Reference count for this adapter object. The adapter can't be
     paused (and detached) before ref_count is dropped back to zero. */
  LONG ref_count;

  /* Standing_by flag */
  unsigned int standing_by : 1;

  /* Media connected/disconnected? */
  unsigned int media_connected : 1;

  /* Power management disabled for this adapter */
  unsigned int power_mgmt_disabled : 1;

  /* Does this adapter have promiscuous mode enabled. */
  unsigned int promiscuous_mode : 1;

  /* Set if this adapter is QuickSec virtual adapter */
  unsigned int is_vnic : 1;

} SshAdapterStruct, *SshAdapter;


#if (NTDDI_VERSION >= NTDDI_WIN6)

typedef struct SshNt6AdapterRec
{
#pragma warning(push)
#pragma warning(disable : 4201)
  /* Generic Windows adapter object; DO NOT move! */
  SshAdapterStruct ;
#pragma warning(pop)

  /* Base miniport LUID used in adapter lookup */
  SshUInt64 luid;
  /* LUID of our filter module */
  SshUInt64 own_luid;
} SshNt6AdapterStruct, *SshNt6Adapter;

#endif /* (NTDDI_VERSION >= NTDDI_WIN6) */


#define ssh_adapter_can_accept_send(a)  \
  ((a)->enable_flags.flags.allow_send == 1)

#define ssh_adapter_can_accept_receive(a)  \
  ((a)->enable_flags.flags.allow_receive == 1)


/*----
  Paremeter structure for ssh_adapter_init_common(). 
  ----*/
typedef struct SshAdapterInitParamsRec
{
  /* Name of underlying device */
  PCWSTR name;
  size_t name_len;

  /* Adapter GUID */
  GUID guid;

  /* Features that are enabled in each adapter state */
  SshAdapterEnableFlagsStruct feature_flags[SSH_NUM_ADAPTER_STATES];
} SshAdapterInitParamsStruct, *SshAdapterInitParams;

/*--------------------------------------------------------------------------
  GENERAL FUNCTIONS FOR ADAPTER CONTROL
  --------------------------------------------------------------------------*/




typedef void (*SshAdapterAttachCompleteCb)(Boolean status,
                                           void *context);



typedef void (*SshAdapterDetachCompleteCb)(void *context);




typedef void (*SshAdapterPauseCompleteCb)(void *context);




typedef void (*SshAdapterRestartCompleteCb)(Boolean status,
                                            void *context);




typedef void (*SshAdapterAttachFn)(SshAdapter adapter,
                                   void *attach_fn_context,
                                   SshAdapterAttachCompleteCb callback,
                                   void *completion_context);




typedef void (*SshAdapterDetachFn)(SshAdapter adapter,
                                   void *detach_fn_context,
                                   SshAdapterDetachCompleteCb callback,
                                   void *completion_context);




typedef void (*SshAdapterRestartFn)(SshAdapter adapter,
                                    void *pause_fn_context,
                                    SshAdapterRestartCompleteCb callback,
                                    void *completion_context);




typedef void (*SshAdapterPauseFn)(SshAdapter adapter,
                                  void *pause_fn_context,
                                  SshAdapterPauseCompleteCb callback,
                                  void *completion_context);




Boolean
ssh_adapter_init_common(SshAdapter adapter,
                        SshInterceptor interceptor,
                        SshAdapterInitParams init_params);




Boolean 
ssh_adapter_attach_common(SshAdapter adapter,
                          SshAdapterAttachFn attach_fn,
                          void *attach_fn_context);




Boolean
ssh_adapter_restart_common(SshAdapter adapter,
                           SshAdapterRestartFn restart_fn,
                           void *restart_fn_context);





void
ssh_adapter_pause_common(SshAdapter adapter,
                         SshAdapterPauseReason reason,
                         SshAdapterPauseFn pause_fn,
                         void *pause_fn_context);




void
ssh_adapter_detach_common(SshAdapter adapter,
                          SshAdapterDetachFn detach_fn,
                          void *detach_fn_context);




void
ssh_adapter_uninit_common(SshAdapter adapter);

/* --------------------------------------------------------------------------
  ssh_adapter_wait_until_state_transition_complete()
  
  Waits until the currently pending state transition (e.g. pausing -> paused)
  completes.
  
  Arguments:
  adapter - adapter object
  
  Returns:
  -
  
  Notes:
  -
  --------------------------------------------------------------------------*/
void
ssh_adapter_wait_until_state_transition_complete(SshAdapter adapter);


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
/* --------------------------------------------------------------------------
  ssh_adapter_device_object_name_get()
  
  Returns the name of device object where we are bound to.
  
  Arguments:
  adapter - adapter object
  name - pointer into Unicode string where the name is copied
  
  Returns:
  TRUE - success, FALSE - otherwise
  
  Notes:
  This function is called when registering SSH Virtual Adapter
  --------------------------------------------------------------------------*/
Boolean
ssh_adapter_device_object_name_get(SshAdapter adapter, 
                                   PNDIS_STRING name);




Boolean
ssh_adapter_set_ip_config(SshAdapter adapter,
                          SshIpAddr addrs,
                          SshUInt16 num_addrs);




Boolean
ssh_adapter_reset_ip_config(SshAdapter adapter);

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/* Default version, can be overridden in platform dependent header file.
   This macro/function need to return FALSE if there is some PLATFORM
   DEPENDENT reason why adapter can not enter to low power state.
   (Notice that adapter state and 'standing_by' flag are already checked in
   common code) */
#define SSH_ADAPTER_CAN_SUSPEND(adapter)          (TRUE)

#ifdef DEBUG_LIGHT

/* Render function to render adapter identifier (interceptor generated name
   and ifnum) and adapter state for %@ format string for ssh_e*printf */
int ssh_adapter_id_st_render(unsigned char *buf, 
                             int buf_size, 
                             int precision,
                             void *datum);

#endif /* DEBUG_LIGHT */


/* --------------------------------------------------------------------------
  ssh_adapter_oid_request_send()

  Sends the specified OID request to the underlying NIC driver.  
  
  Arguments:
  adapter - adapter object
  oid_request - platform independent representation of the OID request
  
  Returns:
  TRUE - success, FALSE - otherwise
  
  Notes:
  This function must be implemented in platform specific code
  --------------------------------------------------------------------------*/
Boolean
ssh_adapter_oid_request_send(SshAdapter adapter,
                             SshOidRequest oid_request);


#ifdef __cplusplus
}
#endif

#endif /* SSH_ADAPTER_COMMON_H */

