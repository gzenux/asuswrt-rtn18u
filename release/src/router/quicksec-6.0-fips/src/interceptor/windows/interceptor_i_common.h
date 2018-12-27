/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Driver type (NDIS intermediate driver vs. NDIS filter driver) independent
   (internal) definitions and functions.
*/

#ifndef SSH_INTERCEPTOR_I_COMMON_H
#define SSH_INTERCEPTOR_I_COMMON_H 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef SSHDIST_IPSEC
/** Include IPsec params if building QuickSec IPsec Toolkit. */
#ifdef SSH_BUILD_IPSEC
#include "ipsec_params.h"

#define SSH_WINDOWS_ENGINE_FLAGS  (SSH_IPSEC_ENGINE_FLAGS)
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */


#include "sshincludes.h"
#include "interceptor.h"
#include "engine.h"
#include "win_os_version.h"
#include "kernel_mutex.h"
#include "task.h"
#include "adapter_common.h" 
#include "ipdevice.h"
#include "iodevice.h"
#include "wrkqueue.h"
#include "registry.h"
#include "debug_trace.h"

/* Default values; can be overriden in interceptor/platform specific header
   file interceptor_i.h */ 
#ifndef SSH_INTERCEPTOR_MAX_ADPATERS
#define SSH_INTERCEPTOR_MAX_ADAPTERS                64
#endif /* SSH_INTERCEPTOR_MAX_ADAPTERS */
#ifndef SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE
#define SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE    400
#endif /* SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE */
#ifndef SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE
#define SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE    800
#endif /* SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE */

/* Define this if you want to pass unknwon HW address packets to the stack 
   when the adapter is in promiscuous mode. */
#define INTERCEPTOR_PASS_PROMISCUOUS_PACKETS

/* Define this if you want to pass loopback packets to the stack. By
   default this is set off, and the packet is silently dropped. */
#define INTERCEPTOR_PASS_LOOPBACK_PACKETS

/* Type flags of IP configuration refresh requests */
    /* Re-read interface information from TCP/IP stack */
#define SSH_IP_REFRESH_INTERFACES    0x00000001
    /* Re-read routing table from TCP/IP stack */
#define SSH_IP_REFRESH_ROUTES        0x00000002
    /* Send interface report to IPSec engine */
#define SSH_IP_REFRESH_REPORT        0x00000004

#define SSH_IP_REFRESH_ALL           (SSH_IP_REFRESH_INTERFACES | \
                                      SSH_IP_REFRESH_ROUTES |     \
                                      SSH_IP_REFRESH_REPORT) 


#define SSH_IP_FORCE_REFRESH_REQUEST(interceptor, type)     \
do                                                          \
{                                                           \
  InterlockedExchange(&interceptor->ip_refresh_type, type); \
  SSH_IP_REFRESH_REQUEST(interceptor);                      \
}                                                           \
while (0);

/* NDIS version definitions */  
#define SSH_NDIS_VERSION_UNKNOWN  0x0000
#define SSH_NDIS_VERSION_5        0x0500
#define SSH_NDIS_VERSION_6        0x0600
#define SSH_NDIS_VERSION_6_1      0x0601
#define SSH_NDIS_VERSION_6_20     0x0614
#define SSH_NDIS_VERSION_6_30     0x061E
#define SSH_NDIS_VERSION_6_40     0x0628

/* Some Ethernet protocol types */
#define SSH_ETHERTYPE_PPPOE_DISCOVERY   0x8863
#define SSH_ETHERTYPE_PPPOE_SESSION     0x8864
#define SSH_ETHERTYPE_8021X             0x888e

typedef struct SshTimeoutManagerRec *SshTimeoutManager;

/* Thread identifier numbers */
#define SSH_WORK_QUEUE_THREAD_ID      0
#define SSH_ROUTING_QUEUE_THREAD_ID   1
#define SSH_IP_CONFIG_THREAD_ID       2
#define SSH_IODEVICE_THREAD_ID        3
#define SSH_DEBUG_TRACE_THREAD_ID     4
#define SSH_LAST_COMMON_THREAD_ID     SSH_DEBUG_TRACE_THREAD_ID 

/* Module states of interceptor driver. */
typedef enum 
{
  SSH_INTERCEPTOR_STATE_HALTED,
  SSH_INTERCEPTOR_STATE_INITIALIZING,
  SSH_INTERCEPTOR_STATE_PAUSED,
  SSH_INTERCEPTOR_STATE_RESTARTING,
  SSH_INTERCEPTOR_STATE_RUNNING,
  SSH_INTERCEPTOR_STATE_ENTERING_LOW_POWER,
  SSH_INTERCEPTOR_STATE_LOW_POWER,
  SSH_INTERCEPTOR_STATE_LEAVING_LOW_POWER,
  SSH_INTERCEPTOR_STATE_PAUSING,
  SSH_INTERCEPTOR_STATE_HALTING
} SshInterceptorState;


/* MIN, MAX macros */
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

/*--------------------------------------------------------------------*/
/* Macros / inline functions for efficient linked list manipulation   */
/* and list validity checks.                                          */
/*--------------------------------------------------------------------*/

/* Checks whether the linked list contains the specified amount of
   items (i.e. that the list is linked correctly). */
#ifdef DEBUG_LIGHT

#define SSH_DEBUG_MODULE "SshInterceptorCommon"

__forceinline void
SSH_ASSERT_LIST_VALID(PLIST_ENTRY list,
                      SshUInt32 item_count)
{
  PLIST_ENTRY entry;
  SshUInt32 i;

  entry = list->Flink;
  for (i = 0; i < item_count; i++)
    {
      entry = entry->Flink;
    }
  SSH_ASSERT(entry == list);
}

__forceinline SshUInt32
SSH_CALC_LIST_ENTRY_COUNT(PLIST_ENTRY list)
{
  PLIST_ENTRY entry = NULL;
  SshUInt32 i = 0;

  entry = list->Flink;
  for (i = 0; entry != list; i++)
  {
    entry = entry->Flink;
  }
  return i;
}

#else /* !DEBUG_LIGHT */

#define SSH_ASSERT_LIST_VALID(list, item_count)

#endif /* DEBUG_LIGHT */


/*--------------------------------------------------------------------*/
/* Macros / inline functions for linked list manipulation and         */
/* list validity checks                                               */
/*--------------------------------------------------------------------*/

/* Efficient "merging" of two doubly-linked lists. Do not use WDM.H
   AppendTailList(), because it seems to add also the list header entry 
   of 'list_to_append' (who knows whether this ia a bug or desired 
   feature?) */
__forceinline void
ssh_append_tail_list(PLIST_ENTRY list,
                     PLIST_ENTRY list_to_append)
{
  /* sanity checks */
  SSH_ASSERT(list != NULL);
  SSH_ASSERT(list_to_append != NULL);

  while (!IsListEmpty(list_to_append))
    {
      PLIST_ENTRY entry = RemoveHeadList(list_to_append);
      InsertTailList(list, entry);
}
}

typedef struct SshPacketPoolRec *SshPacketPool;

/* Interceptor / NDIS version specific packet pool constructor. */
typedef void * (*SshRuntimePacketAlloc)(SshPacketPool pool);
typedef void (*SshRuntimePacketFree)(void *packet, SshPacketPool pool);

/* Generic, packet structure independent, packet pool. */
typedef struct SshPacketPoolRec
{
  /* Linked list of free packets */
  LIST_ENTRY free_packet_list;

  /* Linked list of free buffers */
  LIST_ENTRY free_buffer_list;








  /* Zero based CPU index of this packet pool */
  SshUInt32 cpu_index;

  /* Extra contexts which can be used for storing packet pool specific data.
     This one is not used in generic code. */
  void *buffer_list_context;
  void *packet_list_context;

  SshUInt32 packet_list_size;
  SshUInt32 packet_count;
  SshUInt32 buffer_list_size;
  SshUInt32 buffer_count;

  /* Run time packet alloc/free functions for platforms not allowing 
     pre-allocated packet pools (e.g. Windows Filtering Platform). */
  Boolean use_runtime_np_alloc;
  SshRuntimePacketAlloc runtime_np_alloc;
  SshRuntimePacketFree  runtime_np_free;

  /* Additional packet pool specific context */
  void *ext_context;
} SshPacketPoolStruct;


/* Optional interceptor specific initialization function that will be called
   from ssh_interceptor_init_common() after the platform independend part
   of interceptor has been fully initialized. This function is NOT called
   if initialization has already been failed. */
typedef Boolean (*SshInterceptorInitFn)(SshInterceptor interceptor,
                                        void *init_context);

/* Optional interceptor specific (re)start function that will be called
   from ssh_interceptor_restart_common() after the platform independend part
   of interceptor has been restarted. This function is NOT called if 
   restart operation fails in platform independent code.

   NOTICE! Worker threads (work queue and IP config. thread) are not in
           a running state when this function is called! */
typedef Boolean (*SshInterceptorStartFn)(SshInterceptor interceptor,
                                         void *start_context);

/* Optional interceptor specific pause function that will be called from 
   ssh_interceptor_pause_common() before the platform independend part
   of interceptor has been fully paused. 
   
   NOTICE! Worker threads (work queue and IP config. thread) are not in
           a running state when this function is called! */
typedef void (*SshInterceptorPauseFn)(SshInterceptor interceptor,
                                      void *pause_context);

/* Optional interceptor specific uninitialization function that will be
   called from ssh_interceptor_uninit_common() */
typedef void (*SshInterceptorUninitFn)(SshInterceptor interceptor,
                                       void *uninit_context);

/* Interceptor / NDIS version specific packet pool constructor. */
typedef Boolean (*SshPacketPoolConstructor)(SshInterceptor interceptor);

/* Interceptor / NDIS version specific packet pool destructor. */
typedef void (*SshPacketPoolDestructor)(SshInterceptor interceptor);


/* Parameter structure for ssh_interceptor_init_common() */
typedef struct SshInterceptorInitParamsRec
{
  /* Pointer to DRIVER_OBJECT */
  void *driver_object;

  /* Registry path for the interceptor */
  UNICODE_STRING *registry_path;

  /* Packet pool constructor and destructor functions */
  SshPacketPoolConstructor packet_pool_constructor;
  SshPacketPoolDestructor  packet_pool_destructor;
} SshInterceptorInitParamsStruct, *SshInterceptorInitParams;


/* Optional, interceptor specific function to be called before generic
   IP address and routing table refresh. The refresh operation is interrupted
   (without executing the interceptor independent refresh code) if this 
   function returns FALSE. */
typedef Boolean (*SshInterceptorPreIpRefreshFn)(SshInterceptor interceptor);

/* Optional, interceptor specific function to be called after generic
   IP address and routing table refresh. */
typedef void (*SshInterceptorPostIpRefreshFn)(SshInterceptor interceptor);

/* Parameter structure for ssh_interceptor_restart_common() */
typedef struct SshInterceptorStartParamsRec
{
  /* Flags: */
  /* Should create I/O device? */
  unsigned int create_io_device : 1;

  /* Should raise IRQL before sending PM messages to engine? (This flag 
     should be used if interceptor uses per-CPU packet pools without spin
     lock protection). */
  unsigned int raise_irql_on_pm_engine_calls : 1;

  /* Use asynchronous ssh_interceptor_route(), i.e. run the route lookup 
     at IRQL PASSIVE_LEVEL. */
  unsigned int asynch_interceptor_route : 1;

  /*-------------------------------------------------------------------------
     Additional settings for IP address and routing table retrieval thread */
  
  /* This flag should be used only on platforms where we don't get event
     when IP interfaces or routing table is changed. */
  unsigned int use_polling_ip_refresh : 1;

  /* IP interfae and routing table refresh interval in seconds. If zero, 
     the default interval of two seconds is being used. This setting has 
     effect only when 'use_polling_ip_refresh' flag is also set. */
  SshUInt32 ip_refresh_interval;

  /* This (optional) platform dependent function is called _before_ the
     generic refresh code. If the function returns FALSE, the refresh
     operation is canceled. */
  SshInterceptorPreIpRefreshFn pre_ip_refresh_fn;
  
  /* This (optional) platform dependent function is called _after_ the
     generic IP refresh code. */
  SshInterceptorPostIpRefreshFn post_ip_refresh_fn;
  /*------------------------------------------------------------------------*/
} SshInterceptorStartParamsStruct, *SshInterceptorStartParams;


#ifdef HAS_INTERFACE_NAME_MAPPINGS
/* Mapping between OS specific identifier (GUID, device name, etc...) and
   the name generated by our interceptor */
typedef enum 
{
  SSH_IF_NAME_MAPPING_TYPE_GUID,    /* Interface GUID */
  SSH_IF_NAME_MAPPING_TYPE_DEVICE   /* Device name */
} SshIfNameMappingType;

typedef struct SshIfNameMappingRec
{
  SshInterceptorIfnum ifnum;

  /* Name used by our interceptor */
  unsigned char alias[SSH_ADAPTER_NAME_SIZE_MAX];  

  /* Timestamp of this mapping */
  SshTime timestamp;

  /* mapping type dependent content */
  SshIfNameMappingType type;
  union
  {
    UNICODE_STRING device;
    GUID guid;
  } u;

  /* Tentative flag is set for new adapters in attaching state. If attach
     fails, the tentative mapping is removed */
  unsigned int tentative : 1;
} SshIfNameMappingStruct, *SshIfNameMapping;
#endif /* HAS_INTERFACE_NAME_MAPPINGS */


/* Packet queue (i.e. list of packets waiting to be sent) */
typedef struct SshPacketQueueRec
{
  void *list_head;
  void *list_tail;
  SshUInt32 packets_in_queue; 
} SshPacketQueueStruct, *SshPacketQueue;


/* Cpu specific context data */
typedef struct SshCpuContextRec
{
  /* Packet pool */
  SshPacketPoolStruct packet_pool;

  /* Global packet pool */
  SshKernelMutexStruct global_packet_pool_lock;
  SshPacketPoolStruct global_packet_pool; 

  /* Adapter specific send/receive packet queues */
  SshPacketQueueStruct send_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];
  SshPacketQueueStruct recv_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];

  /* Adapter specific route packet queues */
  SshPacketQueueStruct route_send_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];
  SshPacketQueueStruct route_recv_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];

  /* Adapter specific timeout packet queues */
  SshPacketQueueStruct timeout_send_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];
  SshPacketQueueStruct timeout_recv_queue[SSH_INTERCEPTOR_MAX_ADAPTERS];








  /* Flags: */
  /* Currently executing QuickSec callback */ 
  unsigned int in_packet_cb : 1;
  unsigned int in_route_cb : 1;
  unsigned int in_timeout_cb : 1;

  /* Currently processing enqueud packets */
  unsigned int in_queue_flush : 1; 
  unsigned int in_timeout_queue_flush : 1;
  unsigned int in_route_queue_flush : 1;

  /* Packet(s) waiting in queue. */
  unsigned int packets_in_send_queue : 1;
  unsigned int packets_in_recv_queue : 1;
  unsigned int packets_in_route_send_queue : 1;
  unsigned int packets_in_route_recv_queue : 1;
  unsigned int packets_in_timeout_send_queue : 1;
  unsigned int packets_in_timeout_recv_queue : 1;
} SshCpuContextStruct, *SshCpuContext;


#ifdef NDIS620
/* "Dynamically linked" KeGetCurrentProcessorNumberEx() and 
   KeQueryActiveProcessorCountEx() for Windows 7 and later */
typedef ULONG (*SshGetCurrentProcessorNumber)(void *);
typedef ULONG (*SshQueryActiveProcessorCount)(USHORT group);
#endif /* NDIS620 */


/* Generic interceptor type (NDIS IM driver vs. NDIS filter driver)
   independent packet interceptor for Windows NT series operating
   systems. */
typedef struct SshInterceptorRec
{
  /* Module state of interceptor */
  SshInterceptorState state;

  /* Pointer into the driver object */ 
  void *driver_object;

  /* Operating system */
  SshOsVersion os_version;

  /* Reference count. Interceptor can't be paused before reference count
     is decremented back to zero. */
  LONG ref_count;

#ifdef DEBUG_LIGHT
  /* Debug trace object */
  SshDebugTrace debug_trace;
#endif /* DEBUG_LIGHT */

  /* Should raise IRQL before sending PM messages to engine? (This flag 
     should be used if interceptor uses per-CPU packet pools without spin
     lock protection). */
  unsigned int raise_irql_on_pm_engine_calls : 1;

  /* Use asynchronous ssh_interceptor_route(), i.e. run the route lookup 
     at IRQL PASSIVE_LEVEL. */
  unsigned int asynch_interceptor_route : 1;

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* This flag should be used only on platforms where we don't get event
     when IP interfaces or routing table is changed. */
  unsigned int use_polling_ip_refresh : 1;

  /* Initialization flags */
  unsigned int ipv4_dev_initialized : 1;
#if defined(WITH_IPV6)
  unsigned int ipv6_dev_initialized : 1;
#endif /* WITH_IPV6 */

  /* IP interfae and routing table refresh interval in seconds. If zero, 
     the default interval of two seconds is being used. This setting has 
     effect only when 'use_polling_ip_refresh' flag is also set. */
  SshUInt32 ip_refresh_interval;

  /* This (optional) platform dependent function is called _before_ the
     generic refresh code. If the function returns FALSE, the refresh
     operation is canceled. */
  SshInterceptorPreIpRefreshFn pre_ip_refresh_fn;
  
  /* This (optional) platform dependent function is called _after_ the
     generic IP refresh code. */
  SshInterceptorPostIpRefreshFn post_ip_refresh_fn;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Protocol stack initialized? */
  BOOLEAN net_ready;

  /* Number of CPUs on the hardware platform */
  SshUInt32 processor_count;

#ifdef HAS_IEEE802_3_PASSTHRU
  /* Should we pass "raw" IEEE802.3 traffic. This feature can be activated
     in system registry (e.g. when we run WHQL tests for our interceptor).
     Normally non-IP traffic is dropped by QuickSec engine. */
  BOOLEAN pass_ieee802_3;
#endif /* HAS_IEEE802_3_PASSTHRU */

#ifdef INTERCEPTOR_PASS_PROMISCUOUS_PACKETS
  /* Should we pass promiscuous traffic. This feature can be activated
     in system registry (e.g. when we run WHQL tests for our interceptor).
     Normally promiscuous traffic is dropped by QuickSec engine. */
  BOOLEAN pass_promiscuous;
#endif /* INTERCEPTOR_PASS_PROMISCUOUS_PACKETS */

#ifdef INTERCEPTOR_PASS_LOOPBACK_PACKETS
  /* Should we pass loopback traffic. This feature can be activated
     in system registry (e.g. when we run WHQL tests for our interceptor).
     Normally loopback traffic is dropped by QuickSec engine. */
  BOOLEAN pass_loopback;
#endif /* INTERCEPTOR_PASS_LOOPBACK_PACKETS */

  /* Data members for power management */
  PCALLBACK_OBJECT power_state_cb_obj;
  PVOID power_state_cb_handle;
  ULONG entering_low_power_state;
  BOOLEAN low_power_state;
  SshTime low_power_start_time_sec;

  /* List and count of network adapters */
  LIST_ENTRY adapter_list;
  LONG adapter_cnt;

  /* Adapter array */
  SshAdapter adapter_table[SSH_INTERCEPTOR_MAX_ADAPTERS];

  /* R/W lock for serializing access to adapter_list, adapter_table
     and the contents of the associated adapter structures. */
  SshKernelRWMutexStruct adapter_lock;

#ifdef HAS_INTERFACE_NAME_MAPPINGS
  /* Interface name mappings and the associated R/W lock. When we need to 
     acquire both 'adapter_lock' and 'if_map_lock' the locks must be taken 
     in the correct order:

         1) if_map_lock
         2) adapter_lock

     and released in the opposite order, i.e.

         1) adapter_lock
         2) if_map_lock 
    
     The user of 'adapter_lock' and 'if_map_lock' is not allowed to hold
     any other locks! */
  SshIfNameMapping  if_map[SSH_INTERCEPTOR_MAX_ADAPTERS];
  SshKernelRWMutexStruct if_map_lock;

  /* Registry key for storing interface name mappings */
  SshRegKey if_map_key;
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Thread for handling IP address and routing information queries */
  SshTaskStruct ip_cfg_thread;

  /* Type of refresh and lock for ensuring data integrity */
  LONG  ip_refresh_type;
  SshKernelMutexStruct ip_refresh_lock;

  /* Device interface for IPv4 stack communication */
  SshIPDeviceStruct ip4_dev;
#if defined (WITH_IPV6)
  /* Device interface for IPv6 stack communication */
  SshIPDeviceStruct ip6_dev;
#endif /* WITH_IPV6 */

  /* Callback function for reporting interfaces to the engine */
  SshInterceptorInterfacesCB interfaces_cb;
  /* No interface reports are generated and sent to engine when 
     if_report_disable_count is non-zero. */
  LONG if_report_disable_count;

  /* Route and network interface information */
  SshKernelRWMutexStruct if_lock;
  LIST_ENTRY if_list;

  SshKernelRWMutexStruct ip4_route_lock;
  LIST_ENTRY ip4_route_list;
#if defined (WITH_IPV6)
  SshKernelRWMutexStruct ip6_route_lock;
  LIST_ENTRY ip6_route_list;
#endif /* WITH_IPV6 */
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* I/O device for policy manager communication */
  SshInterceptorIoDevice ipm_device;

  /* Engine object */
  SshEngine engine;
  /* Structure used in engine callback functions */
  void *engine_ctx;

  /* Callback function and context for sending packets to the engine */
  SshInterceptorPacketCB packet_cb;
  void *packet_cb_ctx;

  /* Object that manages all timeout operations  */
  SshTimeoutManager timeout_mgr;

  /* Internal work item queue */ 
  SshNdisWorkQueue work_queue;

  /* Work queue handling asynchronous routing requests */
  SshNdisWorkQueue routing_queue;
  ULONG routing_disable_count;

#ifdef HAS_DELAYED_SEND_THREAD
  /* Thread for sending queued packets. */
  SshTaskStruct delayed_send_thread;
  ULONG delayed_sends;
#endif /* HAS_DELAYED_SEND_THREAD */

  /* Destructor and constructor functions (if given in init params). */
  SshPacketPoolConstructor packet_pool_constructor;
  SshPacketPoolDestructor  packet_pool_destructor;

#ifdef NDIS620
  SshGetCurrentProcessorNumber get_current_cpu_fn;
#endif /* NDIS620 */
  /* CPU specific contexts */
  SshCpuContext cpu_ctx;

#ifdef SSH_IM_INTERCEPTOR
  NDIS_HANDLE wrapper_handle;
#endif /* SSH_IM_INTERCEPTOR */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  LONG va_interface_cnt;
  LONG va_configure_running;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
} SshInterceptorStruct;


#if (NTDDI_VERSION >= NTDDI_WIN6)

typedef struct SshNt6InterceptorRec
{
#pragma warning(push)
#pragma warning(disable : 4201)
  /* Generic Windows interceptor object; DO NOT move! */
  SshInterceptorStruct ;
#pragma warning(pop)

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Address change noticifation handle */
  HANDLE address_change_handle;

  /* Routing table change notification handle */
  HANDLE route_change_handle;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
} SshNt6InterceptorStruct, *SshNt6Interceptor;

#endif /* (NTDDI_VERSION >= NTDDI_WIN6) */


/* Default implementation of SSH_IP_REFRESH_REQUEST macro. This can be 
   (undefined and) redefined in interceptor specific interceptor_i.h */

#define SSH_IP_REFRESH_REQUEST(interceptor)         \
do                                                  \
{                                                   \
  ssh_task_notify(&((interceptor)->ip_cfg_thread),  \
                  SSH_TASK_SIGNAL_NOTIFY);          \
}                                                   \
while (0);

#ifdef DEBUG_LIGHT

/* A macro to dump a packet.  This should not fail since
   ssh_interceptor_packet_next_iteration_read() should not fail. */
#define SSH_DUMP_PACKET(level, str, p)                                       \
do                                                                           \
  {                                                                          \
    size_t __packet_len, __len;                                              \
    const unsigned char *__seg;                                              \
    SshInterceptorPacket __ip = &((p)->ip);                                  \
                                                                             \
    __packet_len = ssh_interceptor_packet_len(__ip);                         \
    SSH_DEBUG((level), ("%s (pkt=0x%p (ipkt=0x%p), len=%lu, protocol=%d, "   \
                        "flags=0x%lx)",                                      \
                        (str), p, __ip, (long)__packet_len,                  \
                        __ip->protocol, __ip->flags));                       \
    ssh_interceptor_packet_reset_iteration(__ip, 0, __packet_len);           \
    while (ssh_interceptor_packet_next_iteration_read(__ip, &__seg, &__len)) \
      {									     \
      SSH_DEBUG_HEXDUMP((level), ("seg len %lu:", (long)__len), __seg,       \
                        __len);                                              \
	ssh_interceptor_packet_done_iteration_read(__ip, &__seg, &__len);    \
      }									     \
    if (__seg != NULL)                                                       \
      ssh_fatal("SSH_DUMP_PACKET freed the packet");                         \
  }                                                                          \
while (0)

#else /* DEBUG_LIGHT */

#define SSH_DUMP_PACKET(level, str, pp)

#endif /* DEBUG_LIGHT */


/*----------------------------------------------------------------------------
  Platform independent initialization funtion for Windows interceptors.

  'init_fn' specifies optional interceptor dependent function for performing
  platform dependent initialization after the common part of interceptor
  object has been fully initialized. Normally this function registers
  the interceptor with NDIS interface.

  When this functions returns, the interceptor state is either 'Paused'
  (successfully initialized) or 'Halted' (error occurred). 
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_init_common(SshInterceptor interceptor,
                            SshInterceptorInitParams init_params,
                            SshInterceptorInitFn init_fn,
                            void *init_fn_context);

/*----------------------------------------------------------------------------
  Platform independent interceptor restart funtion for Windows interceptors.

  'start_fn' specifies optional interceptor dependent restart function
  that will be called after platform independent restart functionality
  has been completed. To prevent extra code complexity and potential 
  race conditions, the working threads (IP config thread and interceptor's
  work queue) are suspended while 'start_fn' is executed. 

  If 'start_fn' returns FALSE, the restart operation is canceled and
  interceptor returns back to 'Paused' state otherwise interceptor enters
  to 'Running' state and ssh_interceptor_restart_common() returns TRUE. 
----------------------------------------------------------------------------*/
Boolean
ssh_interceptor_restart_common(SshInterceptor interceptor,
                               SshInterceptorStartParams start_params,
                               SshInterceptorStartFn start_fn,
                               void *start_fn_context);

/*----------------------------------------------------------------------------
  Platform independent interceptor pause funtion for Windows interceptors.

  'pause_fn' specifies optional interceptor dependent pause function
  that will be called by platform independent code. To prevent extra code 
  complexity and potential race conditions, the working threads (IP config 
  thread and interceptor's work queue) are suspended while 'pause_fn' is 
  executed. 
----------------------------------------------------------------------------*/
void
ssh_interceptor_pause_common(SshInterceptor interceptor,
                             SshInterceptorPauseFn pause_fn,
                             void *pause_fn_context);

/*----------------------------------------------------------------------------
  Platform independent uninitialization funtion for Windows interceptors.

  'uninit_fn' specifies optional interceptor dependent function for performing
  platform dependent uninitialization. Normally this function deregisters
  the interceptor from NDIS interface.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_uninit_common(SshInterceptor interceptor,
                              SshInterceptorUninitFn uninit_fn,
                              void *uninit_fn_context);

/*-------------------------------------------------------------------------
  Suspends the worker threads of an interceptor object. Normally worker
  threads should be suspended during 'pause' and 'restart' operations to
  prevent potential protocol stack deadlocks (i.e. we should not e.g. 
  read the IP address configuration and routing table at that time).
  -----------------------------------------------------------------------*/
void
ssh_interceptor_suspend_worker_threads(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Resumes the worker threads of an interceptor object. Normally worker
  threads should be suspended during 'pause' and 'restart' operations to
  prevent potential protocol stack deadlocks (i.e. we should not e.g. 
  read the IP address configuration and routing table at that time).
  -----------------------------------------------------------------------*/
void
ssh_interceptor_resume_worker_threads(SshInterceptor interceptor);

#ifdef HAS_INTERFACE_NAME_MAPPINGS
/*-------------------------------------------------------------------------
  Adds an interface name mapping for the given adapter.
  -----------------------------------------------------------------------*/
Boolean
ssh_interceptor_add_interface_mapping(SshInterceptor interceptor,
                                      SshAdapter adapter);

/*-------------------------------------------------------------------------
  Frees the specified interface name mapping.
  -----------------------------------------------------------------------*/
void
ssh_interceptor_free_interface_mapping(SshInterceptor interceptor,
                                       SshIfNameMapping if_map);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

/*--------------------------------------------------------------------------
  Increments reference count of adapter object associated with given ifnum.
  Returns pointer to referenced adapter object or NULL if the specified
  adapter does not exist any more.
  --------------------------------------------------------------------------*/
__inline SshAdapter 
ssh_adapter_ref_by_ifnum(SshInterceptor interceptor,
                          SshInterceptorIfnum ifnum)
{
  SshAdapter adapter;
  LONG ref_count;

  if (ifnum >= SSH_INTERCEPTOR_MAX_ADAPTERS)
    return NULL;  

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  adapter = interceptor->adapter_table[ifnum];
  if (adapter)
    {
      ref_count = InterlockedIncrement(&adapter->ref_count);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Incremented adapter %d refcount to %d",
                                   ifnum, ref_count));
      SSH_ASSERT(ref_count > 0);
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  return adapter;
}

/*--------------------------------------------------------------------------
  Decrements the reference count of previously referenced adapter.
  --------------------------------------------------------------------------*/
__inline void
ssh_adapter_release(SshAdapter adapter)
{
  LONG ref_count = InterlockedDecrement(&adapter->ref_count);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Decrement adapter %d refcount to %d",
                               adapter->ifnum, ref_count));
  SSH_ASSERT(ref_count >= 0);
}

/*-------------------------------------------------------------------------
  Initializes kernel timeout module.
  -----------------------------------------------------------------------*/
Boolean
ssh_kernel_timeouts_init(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Uninitializes kernel timeout module.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeouts_uninit(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Suspends kernel timeouts. This function must be called when the operating
  system enters to low power state (suspend/hibernate).
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeouts_suspend(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Resumes kernel timeouts. This function must be called when the operating
  system resumes from low power state (suspend/hibernate) to fully powered
  state.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeouts_resume(SshInterceptor interceptor,
                           SshUInt32 suspend_time_sec,
                           SshUInt32 suspend_time_usec);

/*-------------------------------------------------------------------------
  Creates I/O device for Policy Manager Communication.
  -------------------------------------------------------------------------*/
Boolean
ssh_interceptor_ipm_device_create(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Destroy I/O device for Policy Manager Communication.
  -------------------------------------------------------------------------*/
void
ssh_interceptor_ipm_device_destroy(SshInterceptor interceptor);

/*-------------------------------------------------------------------------
  Signals state of device for Policy Manager Communication.
  -------------------------------------------------------------------------*/
Boolean    
ssh_interceptor_ipm_device_status(INT opened,
                                  PVOID context);

/*-------------------------------------------------------------------------
  Sends message to Policy Manager via I/O Device.
  -------------------------------------------------------------------------*/
Boolean
ssh_interceptor_ipm_device_send_msg(PUCHAR data,
                                    size_t len,
                                    Boolean reliable,
                                    PVOID machine_context);


/*--------------------------------------------------------------------------
 Suspends the interceptor if all adapters are ready to enter low power state.
 --------------------------------------------------------------------------*/
void
ssh_interceptor_suspend_if_idle(SshInterceptor interceptor);


/*-------------------------------------------------------------------------
  Resumes the interceptor. This function must be called when OS is returning
  from a low power state.
  -------------------------------------------------------------------------*/
void
ssh_interceptor_resume(SshInterceptor interceptor); 


/*-------------------------------------------------------------------------
  Checks whether the interceptor is accepted to be loaded on the specified
  operating system. This function must be implemented in platform dependent
  code.
  -------------------------------------------------------------------------*/
Boolean
ssh_interceptor_is_supported_os_version(SshOsVersion os);

/*-------------------------------------------------------------------------
  Flushed a packet. There are few places where the interceptor queues 
  packets for a short period of time. E.g. in routing and timeout handling.
  This function must be implemented in platform dependent code.
  -------------------------------------------------------------------------*/
void
ssh_interceptor_flush_packet_queue(SshInterceptor interceptor,
				   SshPacketQueue queue, Boolean send);

SshInterceptor the_interceptor;

#ifdef DEBUG_LIGHT
/* Renderer function for GUID */
int ssh_guid_render(unsigned char *buf, 
                    int buf_size, 
                    int precision,
                    void *datum);

#undef SSH_DEBUG_MODULE

#endif /* DEBUG_LIGHT */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_INTERCEPTOR_I_COMMON_H */
