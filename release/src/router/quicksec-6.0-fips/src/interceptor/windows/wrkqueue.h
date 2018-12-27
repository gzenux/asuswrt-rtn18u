/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements asynchronous callback facility by using internal queue and a
   worker thread. This allows to execute code at IRQL PASSIVE_LEVEL when
   the caller is running at DISPATCH_LEVEL (as most NDIS callbacks do).
*/

#ifndef SSH_NDIS_WRKQUEUE_H
#define SSH_NDIS_WRKQUEUE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* If this flag is defined, the worker thread will be executed at IRQL
   APC_LEVEL */ 
#define SSH_WORKQUEUE_TIME_CRITICAL   0x00000001

/* If this flag is defined, new work items won't be dynamically allocated
   when the queue is "full". */ 
#define SSH_WORKQUEUE_FIXED_SIZE      0x80000000

/* Public types */

typedef void *SshNdisWorkQueue;

typedef void (__fastcall *SshNdisWorkQueueCbPtr)(void *context);
typedef void (__fastcall *SshNdisWorkQueueCbVoid)(void);

typedef enum
{
  SSH_WORKQUEUE_FN_VOID,
  SSH_WORKQUEUE_FN_1_ARG,
  SSH_WORKQUEUE_FN_2_ARGS,
  SSH_WORKQUEUE_FN_3_ARGS,
  SSH_WORKQUEUE_FN_4_ARGS,
  SSH_WORKQUEUE_FN_5_ARGS
} SshNdisWorkQueueFnArgs;

typedef void *SshNdisWorkQueueFnWithoutTypes;

/* Public functions */ 

Boolean 
ssh_ndis_wrkqueue_initialize(SshNdisWorkQueue *queue_ptr,
                             SshUInt32 queue_id,
                             SshUInt32 flags, 
                             SshUInt8 default_size);

void 
ssh_ndis_wrkqueue_suspend(SshNdisWorkQueue queue);

void 
ssh_ndis_wrkqueue_resume(SshNdisWorkQueue queue);

void 
ssh_ndis_wrkqueue_uninitialize(SshNdisWorkQueue queue);

Boolean __fastcall
ssh_ndis_wrkqueue_queue_raw_item(SshNdisWorkQueue queue,
                                 SshNdisWorkQueueFnWithoutTypes cb,
                                 SshNdisWorkQueueFnArgs num_args,
                                 ...);

#pragma warning(push)
#pragma warning(disable : 4152)
__inline Boolean 
ssh_ndis_wrkqueue_queue_item(SshNdisWorkQueue queue,
                             SshNdisWorkQueueCbPtr callback,
                             void *context)
{
  return ssh_ndis_wrkqueue_queue_raw_item(queue, callback, 
                                          SSH_WORKQUEUE_FN_1_ARG, context);
}    


__inline Boolean
ssh_ndis_wrkqueue_queue_without_args(SshNdisWorkQueue queue,
                                     SshNdisWorkQueueCbVoid callback)
{
  return ssh_ndis_wrkqueue_queue_raw_item(queue, callback, 
                                          SSH_WORKQUEUE_FN_VOID);
}
#pragma warning(pop)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_NDIS_WRKQUEUE_H */
