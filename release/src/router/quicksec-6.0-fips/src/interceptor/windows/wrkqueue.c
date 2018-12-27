/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements asynchronous callback facility by using internal queue and a
   worker thread. This allows to execute code at IRQL PASSIVE_LEVEL (or
   alternatively at APC_LEVEL) when the caller is running at DISPATCH_LEVEL
   (as most NDIS callbacks do).
*/

/* #includes */

#include "sshincludes.h"
#include "interceptor_i.h"
#include "wrkqueue.h"
#include "task.h"


/* #defines */

#define SSH_DEBUG_MODULE "SshInterceptorWorkQueue"

#define SSH_MAX_WORK_ITEM_ARGS  SSH_WORKQUEUE_FN_5_ARGS 

typedef void (__fastcall *SshWorkQueueCbVoid)(void);
typedef void (__fastcall *SshWorkQueueCbPtr)(void *arg1, ...);

typedef void (__fastcall *SshWorkQueueCb1)(void *);
typedef void (__fastcall *SshWorkQueueCb2)(void *, void *);
typedef void (__fastcall *SshWorkQueueCb3)(void *, void *, void *);
typedef void (__fastcall *SshWorkQueueCb4)(void *, void *, void *, void *);
typedef void (__fastcall *SshWorkQueueCb5)(void *, void *, void *, 
                                           void *, void *);

/* Local types */

typedef struct SshWorkItemRec
{
  /* Entry needed for linked lists */ 
  LIST_ENTRY link;

  /* Address and number of arguments of the callback function */ 
  union
  {
    SshWorkQueueCbPtr  fn;
    SshWorkQueueCbVoid fn_void;
    SshWorkQueueCb1    fn_1;
    SshWorkQueueCb2    fn_2;
    SshWorkQueueCb3    fn_3;
    SshWorkQueueCb4    fn_4;
    SshWorkQueueCb5    fn_5;
  } cb;
  SshNdisWorkQueueFnArgs num_args;

  /* Parameters for the callback function */ 
  void *args[SSH_MAX_WORK_ITEM_ARGS];

  /* This flag iddicates whether this is a pre-allocated item */ 
  Boolean pre_allocated;
} SshWorkItemStruct, *SshWorkItem;


typedef struct SshInternalQueueRec
{
  LIST_ENTRY queue;
  LIST_ENTRY item_pool;

  NDIS_SPIN_LOCK queue_lock;
  NDIS_SPIN_LOCK item_pool_lock;

  SshTaskStruct worker_thread;
  SshUInt32 flags;

  /* Actual size of pre_alloc_pool depends from arguments of 
     ssh_ndis_wrkqueue_initialize() */ 
  SshWorkItemStruct pre_alloc_pool[1];
} SshInternalQueueStruct, * SshInternalQueue;


/* Local prototypes */

static void 
ssh_ndis_wrkqueue_loop(SshInternalQueue queue);

static SshWorkItem __fastcall
ssh_ndis_wrkqueue_item_alloc(SshInternalQueue queue);

static void __fastcall
ssh_ndis_wrkqueue_item_free(SshInternalQueue queue, SshWorkItem item);


/* Local variables */



/* Exported functions */

Boolean 
ssh_ndis_wrkqueue_initialize(SshNdisWorkQueue *queue_ptr,
                             SshUInt32 queue_id,
                             SshUInt32 flags,
                             SshUInt8 default_size)
{
  Boolean status = FALSE;

  SSH_ASSERT(queue_ptr != NULL);

  if (default_size > 0)
    {
      SshWorkItem item;
      SshInternalQueue queue;

      queue = ssh_calloc(1, sizeof(*queue) + (default_size) * sizeof(*item));
      if (queue)
        {
          SshTCBStruct tcb;
          SshUInt32 i;

          NdisInitializeListHead(&queue->queue);
          NdisInitializeListHead(&queue->item_pool);

          NdisAllocateSpinLock(&queue->queue_lock);
          NdisAllocateSpinLock(&queue->item_pool_lock);

          queue->flags = flags;

          /* Initialize the pre-allocated work item pool */ 
          for (i = 0; i < default_size; i++)
            {
              item = &queue->pre_alloc_pool[i];
              item->pre_allocated = TRUE;
              InitializeListHead(&item->link);
              InsertTailList(&queue->item_pool, &item->link);
            }

          /* Create worker thread */
          NdisZeroMemory(&tcb, sizeof(tcb));
          tcb.priority = SSH_TASK_PRIORITY_NOCHANGE;
          tcb.exec_type = SSH_TASK_TYPE_EVENT_MONITOR;
          tcb.period_ms = SSH_TASK_EVENT_WAIT_INFINITE;
          if (ssh_task_init(&queue->worker_thread,
                            queue_id, 
                            ssh_ndis_wrkqueue_loop, 
                            queue, &tcb))
            {
              ssh_task_start(&queue->worker_thread);

              *queue_ptr = queue;
              status = TRUE;
            }
          else
            {
              ssh_free(queue);
              *queue_ptr = NULL;
            }
        }
    }

  return status;
}


void 
ssh_ndis_wrkqueue_uninitialize(SshInternalQueue queue)
{
  SSH_ASSERT(queue != NULL);

  ssh_task_stop(&queue->worker_thread);
  ssh_task_uninit(&queue->worker_thread);

  SSH_ASSERT(IsListEmpty(&queue->queue) != FALSE);

  NdisFreeSpinLock(&queue->queue_lock);
  NdisFreeSpinLock(&queue->item_pool_lock);

  ssh_free(queue);
}


void
ssh_ndis_wrkqueue_suspend(SshInternalQueue queue)
{
  ssh_task_suspend(&queue->worker_thread, SSH_TASK_WAIT_INFINITE);
}


void
ssh_ndis_wrkqueue_resume(SshInternalQueue queue)
{
  ssh_task_resume(&queue->worker_thread);
}


Boolean __fastcall 
ssh_ndis_wrkqueue_queue_raw_item(SshInternalQueue queue,
                                 SshNdisWorkQueueFnWithoutTypes callback,
                                 SshNdisWorkQueueFnArgs num_args,
                                 ...)
{
  Boolean status = FALSE;

  if (num_args <= SSH_MAX_WORK_ITEM_ARGS)
    {
      SshWorkItem workitem = ssh_ndis_wrkqueue_item_alloc(queue);

      if (workitem)
        {
          SshUInt8 i;
          va_list va;

#pragma warning(push)
#pragma warning(disable : 4055)
          workitem->cb.fn = (SshWorkQueueCbPtr)callback;
#pragma warning(pop)
          workitem->num_args = num_args;

          /* Read the arguments of the callback function from stack and store
             them into the work item structure */ 
          va_start(va, num_args);

          for (i = 0; i < workitem->num_args; i++)
            workitem->args[i] = va_arg(va, void *);

          va_end(va);

          NdisInterlockedInsertTailList(&queue->queue, &workitem->link,
                                        &queue->queue_lock);
          status = TRUE;
        }

      /* 'Kick' the worker thread in any case. */
      ssh_task_notify(&queue->worker_thread, SSH_TASK_SIGNAL_NOTIFY);
    }

  return status;
}


static void 
ssh_ndis_wrkqueue_loop(SshInternalQueue queue)
{
  SSH_IRQL old_irql;
  PLIST_ENTRY entry;
  Boolean raised_irql = FALSE;

  if (queue->flags & SSH_WORKQUEUE_TIME_CRITICAL)
    {
      SSH_RAISE_IRQL(SSH_APC_LEVEL, &old_irql);
      raised_irql = TRUE;
    }

  while (entry = NdisInterlockedRemoveHeadList(&queue->queue,
                                               &queue->queue_lock))
    {
      SshWorkItem wi = CONTAINING_RECORD(entry, SshWorkItemStruct, link);

      SSH_ASSERT(wi->cb.fn != NULL);

      switch (wi->num_args)
        {
        case SSH_WORKQUEUE_FN_VOID:
          (*(wi->cb.fn_void))();
          break;

        case SSH_WORKQUEUE_FN_1_ARG:
          (*(wi->cb.fn_1))(wi->args[0]);
          break;

        case SSH_WORKQUEUE_FN_2_ARGS:
          (*(wi->cb.fn_2))(wi->args[0], wi->args[1]);
          break;

        case SSH_WORKQUEUE_FN_3_ARGS:
          (*(wi->cb.fn_3))(wi->args[0], wi->args[1], wi->args[2]);
          break;

        case SSH_WORKQUEUE_FN_4_ARGS:
          (*(wi->cb.fn_4))(wi->args[0], wi->args[1], 
                           wi->args[2], wi->args[3]);
          break;

        case SSH_WORKQUEUE_FN_5_ARGS:
          (*(wi->cb.fn_5))(wi->args[0], wi->args[1], wi->args[2], 
                           wi->args[3], wi->args[4]);
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      ssh_ndis_wrkqueue_item_free(queue, wi);
    }

  if (raised_irql)
    {
      SSH_LOWER_IRQL(old_irql);
    }
}


static SshWorkItem __fastcall
ssh_ndis_wrkqueue_item_alloc(SshInternalQueue queue)
{
  PLIST_ENTRY entry;
  SshWorkItem workitem = NULL;

  /* Try to use a pre-allocated item */ 
  entry = NdisInterlockedRemoveHeadList(&queue->item_pool, 
                                        &queue->item_pool_lock);

  if (entry != NULL)
    {
      /* We found a pre-allocated work item */ 
      workitem = CONTAINING_RECORD(entry, SshWorkItemStruct, link);
    }
  else
    {
      /* We have to dynamically allocate a new work item, unless we aren't
         allowed to do it (in which case ssh_ndis_workqueue_item_alloc() will
         just return NULL). */ 
      if ((queue->flags & SSH_WORKQUEUE_FIXED_SIZE) == 0)
        {
          workitem = ssh_malloc(sizeof(SshWorkItemStruct));

          if (workitem != NULL)
            {
              /* This is a temporary work item */ 
              workitem->pre_allocated = FALSE;
            }
        }
    }

  return workitem;
}


static void __fastcall
ssh_ndis_wrkqueue_item_free(SshInternalQueue queue, SshWorkItem item)
{
  if (item->pre_allocated)
    NdisInterlockedInsertTailList(&queue->item_pool, &item->link,
                                  &queue->item_pool_lock);
  else
    ssh_free(item);
}


/* EOF */
