/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic two-directional communications stream between user-mode apps
   and NT kernel mode drivers. Interface to abstract I/O device is common
   between Win9x and NT versions, this is the NT-specific implementation.
*/

/* #includes */

#include "sshincludes.h"
#include "interceptor_i.h"
#include "iodevice.h"
#include "secsys.h"
#include "task.h"
#include "win_os_version.h"
#include "pktizer.h"
#include <ndis.h>
#include <wdmsec.h>

/* #defines */

#define SSH_DEBUG_MODULE "SshInterceptorIodevice"

/* SSH_IODEVICE_QUEUE_SIZE specifies the maximum amout of waiting messages
   before I/O device begins to drop unreliable messages. */
#ifdef DEBUG_LIGHT
/* You may fine-tune this value for your needs. Value 4000 allows forwarding
   of detailed debug output (without too many "lost" debug messages), but on
   the other hand the memory usage "penalty" is SSH_IODEVICE_QUEUE_SIZE times
   sizeof(SshDeviceBufferRec). (4000 * 28 bytes = about 110 kilobytes!) */
#define SSH_IODEVICE_QUEUE_SIZE   4000 
#else 
/* Release version of interceptor should not need a big read queue. */
#define SSH_IODEVICE_QUEUE_SIZE   20
#endif /* DEBUG_LIGHT */

/* Macro for DEVICE_OBJECT -> SshInterceptorIoDevice lookup */
#ifdef SSH_IM_INTERCEPTOR
#define SSH_NTDEV_TO_SSHDEV(pdev) (the_interceptor->ipm_device)
#else /* not SSH_IM_INTERCEPTOR */

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define SSH_NTDEV_TO_SSHDEV(pdev) (the_interceptor->ipm_device)
#else
#define SSH_NTDEV_TO_SSHDEV(pdev) \
  (*((SshInterceptorIoDevice *)pdev->DeviceExtension))
#endif  /* NTDDI_VERSION >= NTDDI_WIN7 */

#endif /* not SSH_IM_INTERCEPTOR */

/* Local types */

typedef struct SshDeviceBufferRec
{
  /* Used to chain segments to the output_queue */
  LIST_ENTRY link;

  /* This entry is used only when the same item is put also to
     the list of unreliable messages. (Optimization) */
  LIST_ENTRY unreliable_list_link;

  /* Pointer to the ssh_malloc'd data */
  unsigned char *addr;

  /* Specifies whether this buffer can be dropped */
  unsigned int reliable:1;
  /* Offset of the data from 'addr' */
  unsigned int offset:31;

  /* Specifies whether this buffer has been pre-allocated (i.e. after
     use it will be inserted back to "free queue") */
  unsigned int pre_allocated:1;
  /* Length of data from 'addr + offset' to the end */
  unsigned int len:31;
} SshDeviceBufferStruct, *SshDeviceBuffer;

#ifdef HAS_IOCTL_HANDLERS
typedef struct SshIoDeviceIoctlHandlerRec
{
  /* For linked lists */
  LIST_ENTRY link;

  /* Registration handle */
  SshIoctlRegHandle handle;

  /* I/O control code */
  SshUInt32 ioctl_code;

  /* Reference count. The handler can not be deleted before the reference
     count is decremented to zero */
  LONG ref_count;

  /* IOCTL request handler */
  SshIoctlHandler ioctl_handler;

  /* IOCTL request cancel function */
  SshIoctlCancelFunction cancel_fn;

  /* Context for 'ioctl_handler' and 'cancel_fn' */
  void *context;
} SshIoDeviceIoctlHandlerStruct, *SshIoDeviceIoctlHandler;


typedef struct SshIoDeviceIoctlRequestRec
{
  /* Public data members accessible in IOCTL handler function */
  SshIoctlRequestStruct public_data;

  /* Private data for the I/O device only */
  struct 
  {
    /* Pointer to associated IRP */
    PIRP irp;

    /* LIST_ENTRY used inside of I/O device */
    LIST_ENTRY link;
  } private_data;
} SshIoDeviceIoctlRequestStruct, *SshIoDeviceIoctlRequest;
#endif /* HAS_IOCTL_HANDLERS */

typedef struct SshInterceptorIoDeviceRec
{
  /* Pointer to interceptor object owning this device */
  SshInterceptor interceptor;

  /* Pointer to the NT device object */
  PDEVICE_OBJECT device;

  /* Pointer to the original (i.e. replaced) security descriptor */
  PSECURITY_DESCRIPTOR orig_sd;

#if (defined(SSH_IM_INTERCEPTOR) || (NTDDI_VERSION >= NTDDI_WIN7))
  NDIS_HANDLE handle;
#endif /* SSH_IM_INTERCEPTOR */

  /* Device name in kernel mode */
  UNICODE_STRING device_name;

  /* Device name in Win32 namespace */
  UNICODE_STRING symlink_name;

  /* If TRUE, device will be destroyed after close IRP has been completed */
  Boolean destroy_after_close;

  /* If TRUE, limit the access to this device for one thread only */
  Boolean exclusive_access;
  /* Number of handles currently open */
  LONG opened_instances;
  /* Non-zero if the I/O device has been created */
  LONG io_device_created;

  /* Routine to execute for each successful create- and close-IRP */
  SshInterceptorIoDeviceStatusCB status_cb;

  /* Routine to execute for each successful write-IRP */
  SshInterceptorIoDeviceReceiveCB receive_cb;

  /* Context information used in callbacks */
  void* cb_context;

  /* Packetizer object */
  SshPacketizerStruct pktizer;

  /* Queue and associated lock for pending read requests (IRPs) */
  LIST_ENTRY read_queue;
  NDIS_SPIN_LOCK read_queue_lock;

  /* Queue and lock for submitted but not yet consumed buffers */
  LIST_ENTRY output_queue;      /* list of waiting SshDeviceBuffers */
  LIST_ENTRY unreliable_output_queue; /* Unreliable items */
  NDIS_SPIN_LOCK output_queue_lock;
  LIST_ENTRY free_list; /* list of free SshDeviceBuffers */
  NDIS_SPIN_LOCK free_list_lock;

  /* Performance optimization */
  SshDeviceBuffer current_read_buf;

  /* Worker thread */
  SshTaskStruct worker_thread;

#ifdef HAS_IOCTL_HANDLERS
  LIST_ENTRY ioctl_handler_list;
  LIST_ENTRY active_ioctl_req_list;
  NDIS_SPIN_LOCK ioctl_handler_list_lock;
  NDIS_SPIN_LOCK ioctl_req_list_lock;
#endif /* #ifdef HAS_IOCTL_HANDLERS */

  /* Pre-allocated buffer descriptors */
  SshDeviceBufferStruct pre_allocated_buffers[SSH_IODEVICE_QUEUE_SIZE];
};

/* Local prototypes */

static void
ssh_interceptor_iodevice_do_reads(SshInterceptorIoDevice io_dev);

DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_create;
DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_close;
DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_cleanup;
DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_read;
DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_write;
DRIVER_DISPATCH ssh_interceptor_iodevice_dispatch_ioctl;
DRIVER_CANCEL ssh_interceptor_iodevice_cancel_queued_read;
#ifdef HAS_IOCTL_HANDLERS
DRIVER_CANCEL ssh_interceptor_iodevice_cancel_queued_ioctl;
#endif /* HAS_IOCTL_HANDLERS */

/* Local variables */


/* Local functions */

/* Locks user mode buffer pages into physical memory and maps the buffer's 
   address into kernel space. */
__inline PVOID
ssh_iodevice_map_buffer(PMDL mdl)
{
  if (mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))
    return (mdl->MappedSystemVa);
  else 
    return (MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached,
                                         NULL, FALSE, LowPagePriority));
}


/* Unlocks the previously locked user mode memory pages. */
__inline VOID
ssh_iodevice_unmap_buffer(PVOID km_addr,
                          PMDL mdl)
{
  MmUnmapLockedPages(km_addr, mdl);
}


__inline SshDeviceBuffer
ssh_iodevice_buffer_alloc(SshInterceptorIoDevice io_dev,
                          Boolean reliable)
{
  SshDeviceBuffer buf = NULL;
  PLIST_ENTRY entry;

  /* 1. Try to get a SshDeviceBuffer from a free list */
  entry = NdisInterlockedRemoveHeadList(&io_dev->free_list,
                                        &io_dev->free_list_lock);
  if (entry)
    buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);

  /* 2. If failed and this is a reliable message, try to replace
     an existing unreliable one */
  if ((buf == NULL) && (reliable))
    {
      NdisAcquireSpinLock(&io_dev->output_queue_lock);
      if (!IsListEmpty(&io_dev->unreliable_output_queue))
        {
          /* We found an existing unreliable message */
          entry = RemoveHeadList(&io_dev->unreliable_output_queue);

          /* We must remove the entry from output_queue too */
          buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct,
                                  unreliable_list_link);

          SSH_ASSERT(buf != io_dev->current_read_buf);

          /* This removes the entry from output_queue */
          RemoveEntryList(&(buf->link));
        }
      NdisReleaseSpinLock(&io_dev->output_queue_lock);

      /* If found, we must delete the old message */
      if (buf != NULL)
        ssh_free(buf->addr);
    }

  /* 3. If still failed, try to allocate memory for a new
     SshDeviceBuffer */
  if ((buf == NULL) && (reliable))
    {
      buf = ssh_malloc(sizeof(*buf));
      if (buf)
        {
          /* This buffer will be deleted after use */
          buf->pre_allocated = 0;
        }
    }

  return buf;
}


__inline void
ssh_iodevice_buffer_free(SshInterceptorIoDevice io_dev, 
                         SshDeviceBuffer buf)
{
  ssh_free(buf->addr);

  if (buf->pre_allocated == 1)
    NdisInterlockedInsertTailList(&io_dev->free_list, &buf->link, 
                                  &io_dev->free_list_lock);
  else
    ssh_free(buf);
}


static Boolean
ssh_iodevice_name_compose(PUNICODE_STRING dest,
                          const unsigned char *prefix,
                          const unsigned char *name)
{
  USHORT prefix_len_a = (USHORT)ssh_ustrlen(prefix);
  USHORT name_len_a   = (USHORT)ssh_ustrlen(name);
  USHORT prefix_len_u = prefix_len_a * sizeof(WCHAR);
  USHORT name_len_u   = name_len_a * sizeof(WCHAR);
  ANSI_STRING ansi_name;
  Boolean status = FALSE;

  ansi_name.Length = prefix_len_a + name_len_a;
  ansi_name.MaximumLength = ansi_name.Length + 1;
  ansi_name.Buffer = ssh_calloc(1, ansi_name.MaximumLength);
  if (ansi_name.Buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
      return FALSE;
    }
  memcpy(ansi_name.Buffer, prefix, prefix_len_a);
  memcpy(&ansi_name.Buffer[prefix_len_a], name, name_len_a);

  dest->Length = prefix_len_u + name_len_u;
  dest->MaximumLength = dest->Length + sizeof(UNICODE_NULL);
  dest->Buffer = ssh_calloc(1, dest->MaximumLength);
  if (dest->Buffer != NULL)
    {
      if (NT_SUCCESS(RtlAnsiStringToUnicodeString(dest, &ansi_name, FALSE)))
        {
          SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                            ("ASCII/ANSI strings '%s' + '%s' successfully "
                             "converted to UNICODE:", prefix, name),
                            (const unsigned char *)dest->Buffer, 
                            dest->Length);

          status = TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("ANSI to UNICODE conversion failed!"));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory!"));
    }

  ssh_free(ansi_name.Buffer);

  return status;
}


/* Exported functions */

SshInterceptorIoDevice
ssh_interceptor_iodevice_alloc(SshInterceptor interceptor,
                               const unsigned char *device_name,
                               Boolean exclusive_access,
                               SshInterceptorIoDeviceStatusCB status_cb,
                               SshInterceptorIoDeviceReceiveCB receive_cb,
                               void *callback_context)
{
  SshInterceptorIoDevice io_dev;

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Allocating I/O device object '%s'", device_name));

  /* Allocate memory for I/O device object */
  io_dev = ssh_calloc(1, sizeof(*io_dev));
  if (io_dev != NULL)
    {
      SshTCBStruct tcb;
      UINT i;

      io_dev->opened_instances = 0;
      io_dev->destroy_after_close = FALSE;
      NdisInitializeListHead(&io_dev->read_queue);
      NdisAllocateSpinLock(&io_dev->read_queue_lock);
      NdisInitializeListHead(&io_dev->output_queue);
      NdisInitializeListHead(&io_dev->unreliable_output_queue);
      NdisAllocateSpinLock(&io_dev->output_queue_lock);
      NdisInitializeListHead(&io_dev->free_list);
      NdisAllocateSpinLock(&io_dev->free_list_lock);

#ifdef HAS_IOCTL_HANDLERS
      NdisInitializeListHead(&io_dev->ioctl_handler_list);
      NdisInitializeListHead(&io_dev->active_ioctl_req_list);
      NdisAllocateSpinLock(&io_dev->ioctl_handler_list_lock);
      NdisAllocateSpinLock(&io_dev->ioctl_req_list_lock);
#endif /* HAS_IOCTL_HANDLERS */

      io_dev->current_read_buf = NULL;

      /* Pre-allocate some "free" SshDeviceBuffers */
      for (i = 0; i < SSH_IODEVICE_QUEUE_SIZE; i++)
        {
          SshDeviceBuffer buf = &(io_dev->pre_allocated_buffers[i]);

          buf->pre_allocated = 1;
          InitializeListHead(&buf->link);
          InsertTailList(&io_dev->free_list, &buf->link);
        }

      /* Initialize worker thread. */
      NdisZeroMemory(&tcb, sizeof(tcb));
      tcb.priority = SSH_TASK_PRIORITY_NOCHANGE;
      tcb.exec_type = SSH_TASK_TYPE_EVENT_MONITOR;
      tcb.period_ms = SSH_TASK_EVENT_WAIT_INFINITE;
      if (!ssh_task_init(&io_dev->worker_thread,
                         SSH_IODEVICE_THREAD_ID, 
                         ssh_interceptor_iodevice_do_reads, 
                         io_dev, &tcb))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize worker thread"));
          ssh_interceptor_iodevice_free(io_dev);
          return NULL;
        }

      /* Create device name */
      if (!ssh_iodevice_name_compose(&io_dev->device_name, 
                                     "\\Device\\", device_name))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to compose device name!"));
          ssh_interceptor_iodevice_free(io_dev);
          return NULL;
        }

      /* Create symbolic link name */
      if (!ssh_iodevice_name_compose(&io_dev->symlink_name,
                                     "\\DosDevices\\Global\\", device_name))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to compose symbolic link name!"));
          ssh_interceptor_iodevice_free(io_dev);
          return NULL;
        }

      SSH_ASSERT(interceptor->ipm_device == NULL);
      interceptor->ipm_device = io_dev;

      io_dev->interceptor = interceptor;
      io_dev->exclusive_access = exclusive_access;
      io_dev->status_cb = status_cb;
      io_dev->receive_cb = receive_cb;
      io_dev->cb_context = callback_context;

      SSH_DEBUG(SSH_D_HIGHOK, 
                ("I/O device object 0x%p successfully allocated and "
                 "initialized", io_dev));
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to allocate memory for I/O device object!"));
    }

  return io_dev;
}


void
ssh_interceptor_iodevice_free(SshInterceptorIoDevice io_dev)
{
  if (io_dev == NULL)
    return;

  ssh_task_uninit(&io_dev->worker_thread);

  NdisFreeSpinLock(&io_dev->read_queue_lock);
  NdisFreeSpinLock(&io_dev->output_queue_lock);
  NdisFreeSpinLock(&io_dev->free_list_lock);

#ifdef HAS_IOCTL_HANDLERS
  while (!IsListEmpty(&io_dev->ioctl_handler_list))
    {
      SshIoDeviceIoctlHandler handler;
      PLIST_ENTRY entry;

      entry = io_dev->ioctl_handler_list.Flink;

      handler = CONTAINING_RECORD(entry, SshIoDeviceIoctlHandlerStruct, link);

      ssh_interceptor_iodevice_deregister_ioctl(io_dev, handler->handle);
    }

  NdisFreeSpinLock(&io_dev->ioctl_list_lock);
  NdisFreeSpinLock(&io_dev->ioctl_req_list_lock);
#endif /* HAS_IOCTL_HANDLERS */

  io_dev->interceptor->ipm_device = NULL;

  ssh_free(io_dev->device_name.Buffer);
  ssh_free(io_dev->symlink_name.Buffer);
  ssh_free(io_dev);

  SSH_DEBUG(SSH_D_HIGHOK, ("I/O device 0x%p freed.", io_dev));
}

Boolean __fastcall
ssh_interceptor_iodevice_create_device(SshInterceptorIoDevice io_dev)
{
  SshInterceptor interceptor;
  PDRIVER_OBJECT driver;
  PSECURITY_DESCRIPTOR new_sd;
  PDRIVER_DISPATCH *fn_table;
  NTSTATUS st;
#ifndef SSH_IM_INTERCEPTOR 
  PDEVICE_OBJECT device;
#else
  PDRIVER_DISPATCH major_function[IRP_MJ_MAXIMUM_FUNCTION + 1];
#endif /* SSH_IM_INTERCEPTOR */

  SSH_ASSERT(io_dev != NULL);  
  SSH_ASSERT(io_dev->interceptor != NULL);
  interceptor = io_dev->interceptor;
  SSH_ASSERT(interceptor->driver_object != NULL);
  driver = interceptor->driver_object;

  NdisAcquireSpinLock(&io_dev->output_queue_lock);
  if (io_dev->destroy_after_close)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Clearing delayed destroy flag..."));
      io_dev->destroy_after_close = FALSE;
    }
  NdisReleaseSpinLock(&io_dev->output_queue_lock);

  if (InterlockedCompareExchange(&io_dev->io_device_created, 1, 0) != 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, 
                ("I/O device already exists; ignoring this call"));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Creating I/O device and symbolic link..."));

#ifndef SSH_IM_INTERCEPTOR
#pragma warning(disable : 28175)
  fn_table = driver->MajorFunction;
#pragma warning(default : 28175)
#else
  RtlZeroMemory(&major_function, sizeof(major_function));
  fn_table = major_function;
#endif /* SSH_IM_INTERCEPTOR */

  /* Initialize dispatch function table */
  fn_table[IRP_MJ_CREATE] = ssh_interceptor_iodevice_dispatch_create;
  fn_table[IRP_MJ_CLOSE] = ssh_interceptor_iodevice_dispatch_close;
  fn_table[IRP_MJ_CLEANUP] = ssh_interceptor_iodevice_dispatch_cleanup;
  fn_table[IRP_MJ_READ] = ssh_interceptor_iodevice_dispatch_read;
  fn_table[IRP_MJ_WRITE] = ssh_interceptor_iodevice_dispatch_write;
  fn_table[IRP_MJ_DEVICE_CONTROL] = ssh_interceptor_iodevice_dispatch_ioctl;

  /* Create the I/O device and symbolic link and limit the access permissions
     of the I/O device. 
  */

#ifdef SSH_IM_INTERCEPTOR
  /* Try to register our I/O device with NDIS */
  st = NdisMRegisterDevice(io_dev->interceptor->wrapper_handle,
                           &io_dev->device_name, 
                           &io_dev->symlink_name,
                           fn_table, 
                           &io_dev->device, 
                           &io_dev->handle);
  if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL, ("NdisMRegisterDevice() failed - %08x", st));
      return FALSE;
    }
#endif /* SSH_IM_INTERCEPTOR */

#if (!defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION < NTDDI_WIN7))
  {
    /* try to create I/O device */
    st = IoCreateDevice(driver, sizeof(void *),
      &io_dev->device_name,
      FILE_DEVICE_NETWORK, 0,
      (BOOLEAN)io_dev->exclusive_access,
      &device);
    if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IoCreateDevice() failed - %08x", st));
      return FALSE;
    }

    io_dev->device = device;
    *((SshInterceptorIoDevice *)device->DeviceExtension) = io_dev;
  }
#endif /* !defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION < NTDDI_WIN7) */

#if (!defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION >= NTDDI_WIN7))
  {
    /* init device object attributes */
    NDIS_DEVICE_OBJECT_ATTRIBUTES ndoa;
    NdisZeroMemory(&ndoa, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));
    ndoa.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    ndoa.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    ndoa.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    ndoa.DeviceName = &io_dev->device_name;
    ndoa.SymbolicName = &io_dev->symlink_name;
    ndoa.MajorFunctions = fn_table;

    /* Allow the kernel, system, and admin complete control over the device. 
       No other users may access the device
    */
    ndoa.DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL_ADM_ALL;

    /* try to  register device with ndis */
    st = NdisRegisterDeviceEx(((SshNdisFilterInterceptor)
      (io_dev->interceptor))->filter_driver_handle,
      &ndoa,
      &io_dev->device,
      &io_dev->handle);

    if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL, ("NdisRegisterDeviceEx() failed - %08x", st));
      return FALSE;
    }
  }

#endif /* !defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION >= NTDDI_WIN7) */

  io_dev->device->AlignmentRequirement = FILE_QUAD_ALIGNMENT;
  io_dev->device->Flags |= DO_DIRECT_IO;

#if (NTDDI_VERSION < NTDDI_WIN7)
  {
    /* Remove world access to newly created device object */
#pragma warning(disable : 28175)
    if (ssh_access_permissions_limit(io_dev->device->SecurityDescriptor,
      &new_sd) != FALSE)
    {
      io_dev->orig_sd = io_dev->device->SecurityDescriptor;
      io_dev->device->SecurityDescriptor = new_sd;
    }
    else
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_access_permissions_limit() failed!"));
    }
#pragma warning(default : 28175)
  }
#endif /* NTDDI_VERSION < NTDDI_WIN7 */

#if (!defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION < NTDDI_WIN7))
  {
    /* earlier than Windows 7 */

    /* Create symbolic link to make device accessible from Win32 */
    st = IoCreateSymbolicLink(&io_dev->symlink_name,
      &io_dev->device_name);
    if (!NT_SUCCESS(st))
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("IoCreateSymbolicLink() failed (%08X): %ls -> %ls",
        st,
        io_dev->symlink_name.Buffer,
        io_dev->device_name.Buffer));

      IoDeleteDevice(io_dev->device);
      return FALSE;
    }
  }

#endif /* !defined(SSH_IM_INTERCEPTOR) && (NTDDI_VERSION <= NTDDI_WIN8) */

  return TRUE;
}


void __fastcall
ssh_interceptor_iodevice_close_device(SshInterceptorIoDevice io_dev)
{
  SSH_ASSERT(io_dev != NULL);

  NdisAcquireSpinLock(&io_dev->output_queue_lock);
  if (InterlockedCompareExchange(&io_dev->opened_instances, 0, 0) != 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("I/O device is still open; marking it for delayed destroy"));
      io_dev->destroy_after_close = TRUE;
      NdisReleaseSpinLock(&io_dev->output_queue_lock);
      return;
    }
  NdisReleaseSpinLock(&io_dev->output_queue_lock);

  if (InterlockedCompareExchange(&io_dev->io_device_created, 0, 1) == 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, 
                ("I/O device already closed; ignoring this call"));
      return;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Closing I/O device and symbolic link..."));

  SSH_ASSERT(ssh_interceptor_iodevice_is_open(io_dev) == FALSE);

#if (NTDDI_VERSION < NTDDI_WIN7)
  {
    /* earlier than Windows 7 */

    /* Restore the original security descriptor back and free the
       modified one */
    if (io_dev->orig_sd)
    {
#pragma warning(disable : 28175)
      ssh_free(io_dev->device->SecurityDescriptor);
      io_dev->device->SecurityDescriptor = io_dev->orig_sd;
#pragma warning(default : 28175)
    }
  }
#endif

#ifdef SSH_IM_INTERCEPTOR
  NdisMDeregisterDevice(io_dev->handle);
#else /* not SSH_IM_INTERCEPTOR */

#if (NTDDI_VERSION >= NTDDI_WIN7)
  /* Windows 7 or later */
  NdisDeregisterDeviceEx(io_dev->handle);
#else
  /* Windows 7 or earlier */
  if (!NT_SUCCESS(IoDeleteSymbolicLink(&io_dev->symlink_name)))
  {
    SSH_DEBUG(SSH_D_FAIL,
      ("ssh_interceptor_iodevice_uninitialize(): "
      "IoDeleteSymbolicLink() failed !"));
  }
  IoDeleteDevice(io_dev->device);
#endif

#endif /* not SSH_IM_INTERCEPTOR */
}


/*

*/
Boolean
ssh_interceptor_iodevice_send(SshInterceptorIoDevice io_dev,
                              unsigned len,
                              unsigned char *addr,
                              Boolean reliable)
{
  SshDeviceBuffer buf = NULL;
  Boolean st = FALSE;


  SSH_ASSERT(addr != NULL); /* Check that we have a valid packet */
  SSH_ASSERT(len > 0);
  SSH_ASSERT(len <= 0x7FFFFFFF); /* Our length field is "only" 31 bits long */

  /* No need to use spin lock (yet), because nothing bad happens if the I/O 
     device will be closed between this check and the moment when we acquire 
     an output queue spin lock. */
  if (InterlockedCompareExchange(&io_dev->opened_instances, 0, 0) != 0)
    buf = ssh_iodevice_buffer_alloc(io_dev, reliable);

  if (buf)
    {
      buf->len = len;
      buf->addr = addr;
      buf->offset = 0;
      if (reliable)
        buf->reliable = 1;
      else
        buf->reliable = 0;

      NdisAcquireSpinLock(&io_dev->output_queue_lock);
      /* This time it's important that we read correct value from
         'io_dev->open', so we must protect also this check with a
         spin lock */
      if (InterlockedCompareExchange(&io_dev->opened_instances, 0, 0) != 0)
        {
          InitializeListHead(&buf->link);
          InsertTailList(&io_dev->output_queue, &buf->link);

          if (reliable == FALSE)
            {
              InitializeListHead(&buf->unreliable_list_link);
              InsertTailList(&io_dev->unreliable_output_queue,
                &buf->unreliable_list_link);
            }

          /* Notify the worker thread */
          ssh_task_notify(&io_dev->worker_thread, SSH_TASK_SIGNAL_NOTIFY);

          st = TRUE;
        }
      NdisReleaseSpinLock(&io_dev->output_queue_lock);
    }

  if (st != TRUE)
    {
      ssh_free(addr);

      if (buf != NULL)
        {
          buf->addr = NULL;
          ssh_iodevice_buffer_free(io_dev, buf);
        }
    }

  return st;
}


#ifdef HAS_IOCTL_HANDLERS
SshIoctlRegHandle
ssh_interceptor_iodevice_register_ioctl(SshInterceptorIoDevice iodevice,
                                        SshUInt32 ioctl_code,
                                        SshIoctlHandler ioctl_handler,
                                        SshIoctlCancelFunction cancel_fn,
                                        void *context)
{
  SshIoDeviceIoctlHandler handler;
  
  SSH_ASSERT(iodevice != NULL);
  SSH_ASSERT(ioctl_code != 0);
  SSH_ASSERT(ioctl_handler != NULL_FNPTR);

  handler = ssh_calloc(1, sizeof(*handler));
  if (handler == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to register handler for IOCTL code 0x%08x", 
                ioctl_code));
      return NULL;
    }

  handler->ioctl_code = ioctl_code;
  handler->handle = handler;
  handler->ioctl_handler = ioctl_handler;
  handler->cancel_fn = cancel_fn;
  handler->context = context;

  NdisAcquireSpinLock(&iodevice->ioctl_handler_list_lock);
  InsertTailList(&iodevice->ioctl_handler_list, &handler->link);
  NdisReleaseSpinLock(&iodevice->ioctl_handler_list_lock);

  return handler->handle;
}


Boolean
ssh_interceptor_iodevice_deregister_ioctl(SshInterceptorIoDevice iodevice,
                                          SshIoctlRegHandle ioctl_handle)
{
  SshIoDeviceIoctlHandler handler = NULL;
  PLIST_ENTRY entry;

  SSH_ASSERT(iodevice != NULL);
  SSH_ASSERT(ioctl_handle != NULL);

  NdisAcquireSpinLock(&iodevice->ioctl_handler_list_lock);
  entry = iodevice->ioctl_handler_list.Flink;
  while (entry != &iodevice->ioctl_handler_list)
    {
      SshIoDeviceIoctlHandler h;

      h = CONTAINING_RECORD(entry, SshIoDeviceIoctlHandlerStruct, link);
    
      if (h->handle == ioctl_handle)
        {
          handler = h;
          RemoveEntryList(&h->link);
          break;
        }
      
      entry = entry->Flink;
    }
  NdisReleaseSpinLock(&iodevice->ioctl_handler_list_lock);

  if (handler != NULL)
    {
      SSH_ASSERT(handler->ref_count == 0);
      ssh_free(handler);

      return TRUE;
    }

  return FALSE;
}


void 
ssh_interceptor_iodevice_complete_ioctl(SshInterceptorIoDevice iodevice,
                                        SshIoctlRequest ioctl_req,
                                        SshIoctlStatus status)
{
  SshIoDeviceIoctlRequest ioctl;
  SshIoDeviceIoctlHandler handler;
  PIRP irp;

  SSH_ASSERT(iodevice != NULL);
  SSH_ASSERT(ioctl_req != NULL);
  SSH_ASSERT(ioctl_req->device == iodevice);

  ioctl = CONTAINING_RECORD(ioctl_req, 
                            SshIoDeviceIoctlRequestStruct, 
                            public_data);

  NdisAcquireSpinLock(&iodevice->ioctl_req_list_lock);
  RemoveEntryList(&ioctl->private_data.link);
  NdisReleaseSpinLock(&iodevice->ioctl_req_list_lock);

  handler = ioctl->public_data.context;

  irp = ioctl->private_data.irp;






#pragma warning(disable: 4311 4312)
  IoSetCancelRoutine(irp, NULL);
#pragma warning(default: 4311 4312)

  switch (status)
    {
    case SSH_IOCTL_RESULT_SUCCESS:
      irp->IoStatus.Status = STATUS_SUCCESS;

      irp->IoStatus.Information = ioctl->public_data.bytes_written;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
      break;

    case SSH_IOCTL_RESULT_FAILURE:
      irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      irp->IoStatus.Information = 0;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
      break;

    case SSH_IOCTL_RESULT_CANCELLED:
      irp->IoStatus.Status = STATUS_CANCELLED;
      irp->IoStatus.Information = 0;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  InterlockedDecrement(&handler->ref_count);




  ssh_free(ioctl);
}
#endif /* HAS_IOCTL_HANDLERS */


Boolean
ssh_interceptor_iodevice_is_open(IN SshInterceptorIoDevice iodevice)
{
  return ((iodevice != NULL) && 
        (InterlockedCompareExchange(&iodevice->opened_instances, 0, 0) != 0));
}


/* Dispatch routines called by NT I/O Manager */

NTSTATUS 
ssh_interceptor_iodevice_dispatch_create(PDEVICE_OBJECT device,
                                         PIRP irp)
{
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);
  LONG instances;

  SSH_ASSERT(io_dev != NULL);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("ssh_interceptor_iodevice_dispatch_create(irp = 0x%p)", irp));

  instances = InterlockedIncrement(&io_dev->opened_instances);

  if (io_dev->exclusive_access && (instances > 1))
    {
      InterlockedDecrement(&io_dev->opened_instances);

      irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      irp->IoStatus.Information = 0;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
      return STATUS_UNSUCCESSFUL;
    }

  if (instances == 1)
    {
      /* Initialize packetizer object */
      ssh_interceptor_pktizer_init(&io_dev->pktizer,
                                   io_dev->receive_cb, io_dev->cb_context);

      /* Start worker thread */
      ssh_task_start(&io_dev->worker_thread);

      if (io_dev->status_cb)
        io_dev->status_cb(TRUE, io_dev->cb_context);
    }

  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("IoCompleteRequest(irp = 0x%p)", irp));

  return STATUS_SUCCESS;
}



NTSTATUS 
ssh_interceptor_iodevice_dispatch_close(PDEVICE_OBJECT device,
                                        PIRP irp)
{
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);
  LONG instances;


  SSH_DEBUG(SSH_D_MIDSTART,
            ("ssh_interceptor_iodevice_dispatch_close(irp = 0x%p)", irp));

  SSH_ASSERT(InterlockedCompareExchange(&io_dev->opened_instances, 0, 0) > 0);

  instances = InterlockedDecrement(&io_dev->opened_instances);

  if (instances == 0)
    {
      /* Uninitialize the packetizer object */
      ssh_interceptor_pktizer_uninit(&io_dev->pktizer);

      /*
        Mark the device as closed and empty the output queue.
        After this no new output buffers will be queued.
      */
      if (io_dev->status_cb)
        io_dev->status_cb(FALSE, io_dev->cb_context);

      /* Complete the pending operations and stop the worker thread. */
      ssh_task_stop(&io_dev->worker_thread);

      /* After our worker thread has terminated, it's totally safe to touch
         output_queue without holding any locks */
      while (!IsListEmpty(&io_dev->output_queue))
        {
          SshDeviceBuffer buf;
          PLIST_ENTRY entry;

          entry = RemoveHeadList(&io_dev->output_queue);
          buf = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);
          if (buf->reliable == 0)
            RemoveEntryList(&buf->unreliable_list_link);

          ssh_iodevice_buffer_free(io_dev, buf);
        };

      if (io_dev->current_read_buf)
        {
          ssh_iodevice_buffer_free(io_dev, io_dev->current_read_buf);
          io_dev->current_read_buf = NULL;
        }
    }

  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  if (io_dev->destroy_after_close)
    {
      ssh_ndis_wrkqueue_queue_item(the_interceptor->work_queue,
                                   ssh_interceptor_iodevice_close_device,
                                   io_dev);
    }

  return STATUS_SUCCESS;
}



NTSTATUS 
ssh_interceptor_iodevice_dispatch_cleanup(PDEVICE_OBJECT device,
                                          PIRP irp)
{
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);
  PLIST_ENTRY entry;


  SSH_DEBUG(SSH_D_MIDSTART,
            ("ssh_interceptor_iodevice_dispatch_cleanup(irp = 0x%p)", irp));

  /* Cancel all pending IRPs */
  while ((entry = NdisInterlockedRemoveHeadList(&io_dev->read_queue,
                                       &io_dev->read_queue_lock)) != NULL)
    {
      PIRP cancelled_irp;

      cancelled_irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
      cancelled_irp->CancelRoutine = NULL;
      cancelled_irp->IoStatus.Status = STATUS_CANCELLED;
      cancelled_irp->IoStatus.Information = 0;
      IoCompleteRequest(cancelled_irp, IO_NO_INCREMENT);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IoCompleteRequest(irp = 0x%p, status = STATUS_CANCELLED)",
                cancelled_irp));
    };

  irp->IoStatus.Status = STATUS_SUCCESS;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("IoCompleteRequest(irp = 0x%p)", irp));

  return STATUS_SUCCESS;
}



NTSTATUS 
ssh_interceptor_iodevice_dispatch_read(PDEVICE_OBJECT device,
                                       PIRP irp)
{
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);


  irp->IoStatus.Status = STATUS_PENDING;
  IoMarkIrpPending(irp);

#pragma warning(disable: 4311 4312)
  IoSetCancelRoutine(irp, ssh_interceptor_iodevice_cancel_queued_read);
#pragma warning(default: 4311 4312)

  /* Insert into the queue of pending read requests */
  NdisInterlockedInsertTailList(&io_dev->read_queue,
                                &irp->Tail.Overlay.ListEntry,
                                &io_dev->read_queue_lock);

  ssh_task_notify(&io_dev->worker_thread, SSH_TASK_SIGNAL_NOTIFY);

  return STATUS_PENDING;
}



NTSTATUS 
ssh_interceptor_iodevice_dispatch_write(PDEVICE_OBJECT device,
                                        PIRP irp)
{
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);
  PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
  unsigned len;
  unsigned char *buf;
  NTSTATUS status = STATUS_UNSUCCESSFUL;


  len = irp_stack->Parameters.Write.Length;
#ifdef SSH_IM_INTERCEPTOR
  /* Aggressive optimization: use directly the user-mode virtual address.
     This is safe as long as we know that we are running in the context of 
     the policy manager thread - and this case we are. */
  buf = MmGetMdlVirtualAddress(irp->MdlAddress);
#else
  buf = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
#endif /* */

  /* We can't expect that write operation always succeeds. We could run out
     of memory in 'packetizer' and later we'll be in a deep trouble if we 
     always tell that we successfully delivered the data... */
  if (ssh_interceptor_pktizer_receive(len, buf, &io_dev->pktizer))
    {
      status = STATUS_SUCCESS;
    }
  else
    {





      len = 0;
      status = STATUS_UNSUCCESSFUL;
    }

  irp->IoStatus.Status = status;
  irp->IoStatus.Information = len;
  IoCompleteRequest(irp, IO_NETWORK_INCREMENT);

  return status;
}

#ifdef HAS_IOCTL_HANDLERS
void 
ssh_interceptor_iodevice_cancel_queued_ioctl(PDEVICE_OBJECT device,
                                             PIRP irp)
{
  SshInterceptorIoDevice io_dev;
  SshIoctlCancelFunction cancel_fn = NULL_FNPTR;
  void *cancel_context;
  SshIoctlCancelID cancel_id;
  Boolean cancelled = FALSE;
  PLIST_ENTRY entry;

  /* Cancel processing is protected by queue-specific lock, not by the (one 
     and only) system-wide Cancel lock */
  IoReleaseCancelSpinLock(irp->CancelIrql);

  io_dev = SSH_NTDEV_TO_SSHDEV(device);

  NdisAcquireSpinLock(&io_dev->ioctl_req_list_lock);
  entry = io_dev->active_ioctl_req_list.Flink;
  while (entry != &io_dev->active_ioctl_req_list)
    {
      SshIoDeviceIoctlRequest ioctl;
      SshIoDeviceIoctlHandler handler;

      ioctl = CONTAINING_RECORD(entry, 
                                SshIoDeviceIoctlRequestStruct, 
                                private_data.link);

      if (ioctl->private_data.irp == irp)
        {
          handler = ioctl->public_data.context;

          cancel_fn = handler->cancel_fn;
          cancel_context = handler->context;
          cancel_id = ioctl->public_data.cancel_id;
          
          break;
        }

      entry = entry->Flink;
    }
  NdisReleaseSpinLock(&io_dev->ioctl_req_list_lock);

  if (cancel_fn != NULL_FNPTR)
    {
      cancelled = (*cancel_fn)(cancel_context, cancel_id);
    }

  if (cancelled == FALSE)
    {
      /* We have a bug somewhere if we end up here */
      SSH_NOTREACHED;   
    }
}
#endif /* HAS_IOCTL_HANDLERS */


NTSTATUS
ssh_interceptor_iodevice_dispatch_ioctl(PDEVICE_OBJECT device,
                                        PIRP irp)
{
#ifdef HAS_IOCTL_HANDLERS
  PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(irp);
  ULONG ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;
  SshInterceptorIoDevice io_dev = SSH_NTDEV_TO_SSHDEV(device);
  SshIoDeviceIoctlHandler handler = NULL;
  PLIST_ENTRY entry;

  NdisAcquireSpinLock(&io_dev->ioctl_handler_list_lock);
  entry = io_dev->ioctl_handler_list.Flink;
  while (entry != &io_dev->ioctl_handler_list)
    {
      SshIoDeviceIoctlHandler h;

      h = CONTAINING_RECORD(entry, SshIoDeviceIoctlHandlerStruct, link);

      if (h->ioctl_code == ioctl_code)
        {
          handler = h;
          InterlockedIncrement(&handler->ref_count);
          break;
        }

      entry = entry->Flink;
    }
  NdisReleaseSpinLock(&io_dev->ioctl_handler_list_lock);

  if (handler != NULL)
    {
      SshIoDeviceIoctlRequest ioctl;




      ioctl = ssh_calloc(1, sizeof(*ioctl));
      if (ioctl == NULL)
        {
          irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
          irp->IoStatus.Information = 0;
          IoCompleteRequest(irp, IO_NO_INCREMENT);

          return STATUS_UNSUCCESSFUL;
        }

      /* Initialize te IOCTL request */
      ioctl->public_data.device = io_dev;
      ioctl->public_data.ioctl_code = ioctl_code;
      ioctl->public_data.context = handler;                  
      ioctl->public_data.cancel_id = ioctl; 
      ioctl->public_data.input_buf_len = 
        io_stack->Parameters.DeviceIoControl.InputBufferLength;
      ioctl->public_data.output_buf_len = 
        io_stack->Parameters.DeviceIoControl.OutputBufferLength;

      switch (ioctl_code & 0x00000003)
        {
        case METHOD_BUFFERED:
          ioctl->public_data.input_buf = irp->AssociatedIrp.SystemBuffer;
          ioctl->public_data.output_buf = irp->AssociatedIrp.SystemBuffer;
          break;

        case METHOD_NEITHER:
          ioctl->public_data.input_buf = 
            io_stack->Parameters.DeviceIoControl.Type3InputBuffer;
          ioctl->public_data.output_buf = irp->UserBuffer;
          break;




        case METHOD_IN_DIRECT:  
        case METHOD_OUT_DIRECT:
        default:
          SSH_NOTREACHED;
          break;
        }
      ioctl->public_data.bytes_read = 0;
      ioctl->public_data.bytes_written = 0;
      ioctl->private_data.irp = irp;
      NdisAcquireSpinLock(&io_dev->ioctl_req_list_lock);
      InsertTailList(&io_dev->active_ioctl_req_list,
		     &ioctl->private_data.link);
      NdisReleaseSpinLock(&io_dev->ioctl_req_list_lock);

      irp->IoStatus.Status = STATUS_PENDING;
      IoMarkIrpPending(irp);

#pragma warning(disable: 4311 4312)
      IoSetCancelRoutine(irp, ssh_interceptor_iodevice_cancel_queued_ioctl);
#pragma warning(default: 4311 4312)

      (*(handler->ioctl_handler))(handler->context, &ioctl->public_data);

      return STATUS_PENDING;
    }
#endif /* HAS_IOCTL_HANDLERS */

  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  irp->IoStatus.Information = 0;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  return STATUS_NOT_SUPPORTED;
}

/*
  Internal helpers
*/

static void 
ssh_interceptor_iodevice_do_reads(SshInterceptorIoDevice io_dev)
{
  SshDeviceBuffer buffer;
  PIO_STACK_LOCATION irp_stack = NULL;
  char *dest = NULL;
  char *base_addr = NULL;
  PIRP irp = NULL;

  NdisAcquireSpinLock(&io_dev->output_queue_lock);
  buffer = io_dev->current_read_buf;
  NdisReleaseSpinLock(&io_dev->output_queue_lock);

  /* Complete as many queued output buffers and pending reads as possible */
  while (TRUE)
    {
      PLIST_ENTRY entry;
      unsigned bytes_copied;

      /* Try to find some data to write */
      if (buffer == NULL)
        {
          NdisAcquireSpinLock(&io_dev->output_queue_lock);
          if (!IsListEmpty(&io_dev->output_queue))
            {
              entry = RemoveHeadList(&io_dev->output_queue);
              buffer = CONTAINING_RECORD(entry, SshDeviceBufferStruct, link);
              /* If this is an unreliable message, it must also be removed
                 from the unreliable_output_queue! */
              if (buffer->reliable == 0)
                RemoveEntryList(&buffer->unreliable_list_link);
            }
          io_dev->current_read_buf = buffer;
          NdisReleaseSpinLock(&io_dev->output_queue_lock);

          /* Exit the loop if no data was available in output queue */
          if (buffer == NULL)
            goto complete;  
        }

      /* Try to find queued read IRP */
      if (irp == NULL)
        {
          entry = NdisInterlockedRemoveHeadList(&io_dev->read_queue,
                                                &io_dev->read_queue_lock);
          if (entry)
            {
              irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
              irp_stack = IoGetCurrentIrpStackLocation(irp);

              /* There is no need to check for canceled status, because
                 cancelation is protected by the same lock as the queue
                 itself. We may actually pop off an IRP for which cancel
                 has already been issued, but we can complete it as usual. */
#pragma warning(disable: 4311 4312)
              IoSetCancelRoutine(irp, NULL);
#pragma warning(default: 4311 4312)
              irp->IoStatus.Information = 0;
              irp->IoStatus.Status = STATUS_SUCCESS;

              base_addr = ssh_iodevice_map_buffer(irp->MdlAddress);
              if (base_addr == NULL)
                {
                  /* Mapping of user-mode buffer could fail if the system is
                     very low on resources. */
                  IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
                  irp = NULL;
                  continue;
                }

              dest = base_addr;
            }
          else
            {
              /* No read IRPs available, exit the loop */
              goto complete;
            }
        }

      /* We copy either the whole buffer or part of it if there isn't enough
         space left in the currently processed read IRP. */
      bytes_copied = buffer->len;
      if (irp->IoStatus.Information + bytes_copied >
          irp_stack->Parameters.Read.Length)
        {
          bytes_copied = irp_stack->Parameters.Read.Length -
                         (unsigned int)irp->IoStatus.Information;
        }

      NdisMoveMemory(dest, buffer->addr + buffer->offset, bytes_copied);

      buffer->offset += bytes_copied;
      buffer->len -= bytes_copied;
      if (buffer->len == 0)
        {
          NdisAcquireSpinLock(&io_dev->output_queue_lock);
          io_dev->current_read_buf = NULL;
          NdisReleaseSpinLock(&io_dev->output_queue_lock);

          ssh_iodevice_buffer_free(io_dev, buffer); 

          buffer = NULL;
        }

      irp->IoStatus.Information += bytes_copied;
      dest += bytes_copied;

      /* If the IRP is now "full", complete the request */
      if (irp->IoStatus.Information == irp_stack->Parameters.Read.Length)
        {
          ssh_iodevice_unmap_buffer(base_addr, irp->MdlAddress);
          IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
          irp = NULL;
          base_addr = NULL;
        }
    }

complete:

  /* We should also complete the partially filled IRP, if any */
  if (irp)
    {
      ssh_iodevice_unmap_buffer(base_addr, irp->MdlAddress);
      IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
    }
}



/*
  Cancel routine for queued read operations initiated by user-mode daemons.
*/
void 
ssh_interceptor_iodevice_cancel_queued_read(PDEVICE_OBJECT device,
                                            PIRP irp)
{
  SshInterceptorIoDevice io_dev;
  PLIST_ENTRY entry, next_entry;
  LIST_ENTRY  cancelled_irps;

  /* Cancel processing is protected by queue-specific lock, not by the (one 
     and only) system-wide Cancel lock */
  IoReleaseCancelSpinLock(irp->CancelIrql);

  io_dev = SSH_NTDEV_TO_SSHDEV(device);

  NdisInitializeListHead(&cancelled_irps);

  SSH_DEBUG(SSH_D_MIDSTART, 
            ("ssh_interceptor_iodevice_cancel_queued_read()"));

  /* Find and dequeue all canceled IRPs (not just the one given as argument).
     Complete the IRPs after releasing the spin lock. */
  NdisAcquireSpinLock(&io_dev->read_queue_lock);
  entry = io_dev->read_queue.Flink;
  while (entry && (entry != &io_dev->read_queue))
    {
      next_entry = entry->Flink;

      irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
      if (irp->Cancel)
        {
          RemoveEntryList(entry);
          InitializeListHead(entry);
          InsertTailList(&cancelled_irps, entry);
        }

      entry = next_entry;
    }
  NdisReleaseSpinLock(&io_dev->read_queue_lock);

  while (!IsListEmpty(&cancelled_irps))
    {
      entry = RemoveHeadList(&cancelled_irps);

      irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

      irp->IoStatus.Status = STATUS_CANCELLED;
      irp->IoStatus.Information = 0;
      IoCompleteRequest(irp, IO_NO_INCREMENT);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IoCompleteRequest(irp = 0x%p, status = STATUS_CANCELLED)",
                irp));
    };
}

/* EOF */
