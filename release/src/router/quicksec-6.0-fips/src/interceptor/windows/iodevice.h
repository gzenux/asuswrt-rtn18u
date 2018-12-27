/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic two-directional communications stream between user-mode
   applications and kernel mode drivers. There exist separate
   implementations for both Windows desktop (Windows XP and later) and
   Mobile (Windows CE / Windows Mobile) platforms.
*/

#ifndef SSH_INTERCEPTOR_IODEVICE_H
#define SSH_INTERCEPTOR_IODEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/* Forward declaration for Interceptor I/O Device object structure */
typedef struct SshInterceptorIoDeviceRec *SshInterceptorIoDevice;

/* Callback function for indicating I/O Device state to Interceptor/Engine */
typedef Boolean (*SshInterceptorIoDeviceStatusCB)(int opened, 
                                                  void *context);

#ifdef HAS_IOCTL_HANDLERS
/* IOCTL request callback */
typedef enum
{
  SSH_IOCTL_RESULT_SUCCESS,
  SSH_IOCTL_RESULT_FAILURE,
  SSH_IOCTL_RESULT_CANCELLED
} SshIoctlStatus;

typedef void * SshIoctlRegHandle;
typedef void * SshIoctlCancelID;

typedef struct SshIoctlRequestRec
{
  /* Read-only data members that can be modified only by the I/O device */
  SshInterceptorIoDevice device;  /* I/O device owning this request */
  SshUInt32 ioctl_code;           /* I/O control code */
  void *context;                  /* I/O device specific context */
  SshIoctlCancelID cancel_id;     /* Cancel ID of this IOCTL request */
  SshUInt32 input_buf_len;        /* Length (in bytes) of 'input_buf' */
  SshUInt32 output_buf_len;       /* Length (in bytes) of 'outout_buf' */

  /* Data buffer that can be read/written by the IOCTL handler. */
  unsigned char *input_buf;
  unsigned char *output_buf;

  /* 'bytes_read' and 'bytes_writtne' must be filled by IOCTL handler before 
     the IOCTL has been completed. */
  SshUInt32 bytes_read;    
  SshUInt32 bytes_written;

  /* These can be freely used by the interceptor when it has the ownerhip
     of this IOCTL request. */
  LIST_ENTRY link;       
  void *scratch;        
  
} SshIoctlRequestStruct, *SshIoctlRequest;

/* Function type for IOCTL request handler.  */
typedef void (*SshIoctlHandler)(void *context,
                                SshIoctlRequest request);

/* Function type for IOCTL request cancel function. */
typedef Boolean (*SshIoctlCancelFunction)(void *context,
                                          SshIoctlCancelID cancel_id);
#endif /* HAS_IOCTL_HANDLERS */

/* Callback function for reading PM supplied data from I/O Device object */
typedef Boolean  
(__fastcall *SshInterceptorIoDeviceReceiveCB)(int len, 
                                              unsigned char *buf, 
                                              void *context);

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Constructor for I/O Device Object. This function only creates and 
  initializes the _object_, it doesn't create the actual I/O device. 

  IRQL requirement: PASSIVE_LEVEL
  --------------------------------------------------------------------------*/
SshInterceptorIoDevice
ssh_interceptor_iodevice_alloc(SshInterceptor interceptor,
                               const unsigned char *device_name,
                               Boolean exclusive_access,
                               SshInterceptorIoDeviceStatusCB status_cb,
                               SshInterceptorIoDeviceReceiveCB receive_cb,
                               void *callback_context);


/*--------------------------------------------------------------------------
  Creates an I/O device and a user-mode accessible symbolic link for it. For
  improved security, the created device has limited access permissions so it
  can be opened only by processes having either 'System' or administrative
  privileges (this applies only to desktop Windows operating systems, not
  Windows CE / Windows Mobile).

  The device object 'device' must be allocated and initialized by 
  ssh_interceptor_iodevice_alloc() prior calling this funtion.

  ssh_interceptor_iodevice_create_device() may be called consecutively 
  multiple times, but (quite self-obviously) only one I/O device is created. 

  Return value is TRUE when either the I/O device was successfully created or
  the I/O already exists (in case this function is called multiple 
  consecutive times) and FALSE if the I/O could not be created.

  IRQL requirement: PASSIVE_LEVEL
  --------------------------------------------------------------------------*/
Boolean __fastcall
ssh_interceptor_iodevice_create_device(SshInterceptorIoDevice device);


/*--------------------------------------------------------------------------
  Closes and destroys a previously created I/O device. 

  If a user mode process (i.e. the QuickSec policy manager) is currently 
  using the I/O device the device is marked for delayed destruction and it 
  will be destroyed when the user-mode handle to the device object is closed 
  (i.e. when the policy manager is stopped.)

  I/O device marked for delayed destruction can be "re-created" by calling
  ssh_interceptor_io_device_create_device(), in which case only the delayed
  destruction flag is cleared and the I/O device remains functioning normally.

  IRQL requirement: PASSIVE_LEVEL
  --------------------------------------------------------------------------*/
void __fastcall
ssh_interceptor_iodevice_close_device(SshInterceptorIoDevice device);


/*--------------------------------------------------------------------------
  Destructor for I/O Device Object

  IRQL requirement: PASSIVE_LEVEL
  --------------------------------------------------------------------------*/
void
ssh_interceptor_iodevice_free(SshInterceptorIoDevice device);


#ifdef HAS_IOCTL_HANDLERS
/*--------------------------------------------------------------------------
  Registers additional IOCTL handler

  IRQL requirement: <= DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
SshIoctlRegHandle
ssh_interceptor_iodevice_register_ioctl(SshInterceptorIoDevice device,
                                        SshUInt32 ioctl_code,
                                        SshIoctlHandler ioctl_handler,
                                        SshIoctlCancelFunction cancel_fn,
                                        void *context);

/*--------------------------------------------------------------------------
  Unregisters existing IOCTL handler

  IRQL requirement: <= DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_iodevice_deregister_ioctl(SshInterceptorIoDevice device,
                                          SshIoctlRegHandle ioctl_handle);

/*--------------------------------------------------------------------------
  IOCTL completion handler. This must be called by the interceptor every time
  a IOCTL request is completed (either synchronously or asynchronously) or
  the request is cancelled.

  IRQL requirement: <= DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
void
ssh_interceptor_iodevice_complete_ioctl(SshInterceptorIoDevice device,
                                        SshIoctlRequest ioctl_req,
                                        SshIoctlStatus status);
#endif /* HAS_IOCTL_HANDLERS */

/*--------------------------------------------------------------------------
  Sends data to PM via I/O Device Object

  IRQL requirement: <= DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_iodevice_send(SshInterceptorIoDevice device,
                              SshUInt32 len,
                              unsigned char *addr,
                              Boolean reliable);

/*--------------------------------------------------------------------------
  Returns TRUE if I/O Device is opened, FALSE otherwise.

  IRQL requirement: <= DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_iodevice_is_open(SshInterceptorIoDevice device);

#ifdef __cplusplus
}
#endif

#endif /* SSH_INTERCEPTOR_IODEVICE_H */
