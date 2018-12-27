/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform independent support for writing a debug trace into persistent
   storage.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "file_io.h"

#ifdef DEBUG_LIGHT

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/* MAXIMUM VALUE for trace generations is 100, unless you are willing to
   modify the code accordingly... */
#define SSH_DEBUG_TRACE_GENERATIONS   4

/* The trace output filemane definition must contain '%02u' placeholder for
   the trace generation number */
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#define SSH_DEBUG_TRACE_FILENAME      "QuickSec_Trace%02u.txt"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/* Comment to be written into the output file in case the maximum trace 
   length limit is met. */
#define SSH_DEBUG_TRACE_FULL_TEXT     \
  ((const unsigned char *)"\r\nTrace full!\r\n")

#define SSH_PARAMETERS_KEY_NAME       L"Parameters"

typedef struct SshDebugTraceRec
{
  /* Lock for concurrency control */
  SshKernelMutexStruct lock;

  /* Worker thread for writing debug log (we can not do that directly on
     a raised IRQL) */
  SshTaskStruct writer_thread;

  /* Debug message list */
  LIST_ENTRY list;
  LONG msg_count;

  /* Trace generation */
  SshUInt32 generation;

  /* Size limit of the debug log */
  SshUInt64 bytes_left;

  /* Debug output file */
  unsigned char filename[256];
  HANDLE handle;

  /* For timestamps */
  LARGE_INTEGER start_perf_cntr;
  LARGE_INTEGER perf_cntr_freq;

  /* Flags */
  unsigned int writer_thread_initialized;
} SshDebugTraceStruct;


typedef struct SshDebugMsgRec
{
  /* List entry for keeping debug messages in a linked list */
  LIST_ENTRY list_entry; 
 
  /* Currently executing CPU */
  int cpu;
  /* Current IRQL */
  SSH_IRQL irql;

  /* Timestamp */
  SshTime ts_s;
  SshUInt32 ts_ns;

  /* Variable length debug message is appended here */
  unsigned char msg[1];  
} SshDebugMsgStruct, *SshDebugMsg;

static void
ssh_debug_trace_timestamp(SshDebugTrace debug_trace,
                          SshTime *time_s,
                          SshUInt32 *time_us);

static Boolean
ssh_debug_trace_write_msg(SshDebugTrace debug_trace,
                          SshDebugMsg debug_msg);

static void
ssh_debug_trace_writer_thread(SshDebugTrace debug_trace);

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

SshDebugTrace
ssh_debug_trace_create(PUNICODE_STRING reg_path)
{
  SshDebugTrace debug_trace;
  SshTCBStruct tcb;
  SshRegKey conf_key = NULL;
  SshRegKey param_key = NULL;
  SshRegDWord trace_enable;
  SshRegDWord max_size;
  unsigned char *output_dir = NULL;
  unsigned char *debug_str = NULL;
  int len;

  debug_trace = ssh_calloc(1, sizeof(*debug_trace));
  if (debug_trace == NULL)
    return NULL;

  ssh_kernel_mutex_init(&debug_trace->lock);

  InitializeListHead(&debug_trace->list);
  debug_trace->msg_count = 0;

  /* Read debug trace settings from system registry */
  conf_key = ssh_registry_key_open_unicode(NULL, NULL, reg_path);
  if (conf_key == NULL)
    goto failed;

  param_key = ssh_registry_key_open(conf_key, NULL, SSH_PARAMETERS_KEY_NAME);
  if (param_key == NULL)
    goto failed;

  if (!ssh_registry_dword_get(param_key, L"TraceEnable", &trace_enable)
      || (trace_enable == 0))
    goto disable_trace;

  /* Read debug level string. Use "0" if it does not exist */
  if (!ssh_registry_asciiz_string_get(param_key, L"TraceString", &debug_str))
    debug_str = ssh_strdup("0");
  if (debug_str == NULL)
    goto disable_trace;

  /* Read the generation of the last trace and increment/wraparound
     it. Create it if it does not exist (ignoring error). */
  if (ssh_registry_dword_get(param_key, L"TraceGeneration", 
                             (SshRegDWord *)&debug_trace->generation))
    {
      debug_trace->generation++;
      if (debug_trace->generation >= SSH_DEBUG_TRACE_GENERATIONS)
        debug_trace->generation = 0;
    }
  else
    {
      debug_trace->generation = 0;
    }
  ssh_registry_dword_set(param_key, L"TraceGeneration", 
                         debug_trace->generation);

  /* Read the directory setting for trace files. */
  if (!ssh_registry_asciiz_string_get(param_key, L"TraceDirectory", 
                                      &output_dir))
    {
      output_dir = ssh_strdup("\\SystemRoot\\");
    }
  if (ssh_ustrlen(output_dir) == 0)
    {  
      len = ssh_snprintf(debug_trace->filename,
                         sizeof(debug_trace->filename),
                         SSH_DEBUG_TRACE_FILENAME, 
                         debug_trace->generation);
    }
  else
    {
      SshUInt32 buff_size = sizeof(debug_trace->filename);
      unsigned char *buff_ptr = debug_trace->filename;
      int dir_len = ssh_ustrlen(output_dir);

      if ((dir_len > 3) && (output_dir[1] == ':') && (output_dir[2] == '\\'))
        {
          /* "\??\" a.k.a. "\DosDevices\" */
          const unsigned char dd_prefix[4] = {'\\','?','?','\\'};

          memcpy(buff_ptr, dd_prefix, sizeof(dd_prefix));
          buff_ptr += sizeof(dd_prefix);
          buff_size -= sizeof(dd_prefix);
        }

      if ((dir_len < 0) || ((SshUInt32)dir_len >= buff_size))
        goto failed;

      memcpy(buff_ptr, output_dir, dir_len);
      if (output_dir[dir_len - 1] != '\\')
        {
          buff_ptr[dir_len] = '\\';
          dir_len++;
        }
      buff_ptr += dir_len;
      buff_size -= (SshUInt32)dir_len;

      len = ssh_snprintf(buff_ptr, buff_size,
                         SSH_DEBUG_TRACE_FILENAME,
                         debug_trace->generation);
      if (len < 0)
        goto failed;
    }
  ssh_free(output_dir);

  /* Read the maximum length (in megabytes) of the trace. If unlimited,
     use all available storage space (if needed)... */
  if (ssh_registry_dword_get(param_key, L"TraceMaxSize", &max_size)
      && (max_size != 0))
    {
      debug_trace->bytes_left = (SshUInt64)max_size * 1024 * 1024;
    }
  else
    {
      debug_trace->bytes_left = (SshUInt64)-1;
    }
  debug_trace->bytes_left -= ssh_ustrlen(SSH_DEBUG_TRACE_FULL_TEXT);

  /* Debug trace enabled. Start writer thread */
  memset(&tcb, 0x00, sizeof(tcb));
  tcb.priority = SSH_TASK_PRIORITY_NOCHANGE;
  tcb.exec_type = SSH_TASK_TYPE_EVENT_MONITOR;
  tcb.period_ms = SSH_TASK_EVENT_WAIT_INFINITE;
  if (!ssh_task_init(&debug_trace->writer_thread,
                     SSH_DEBUG_TRACE_THREAD_ID,
                     ssh_debug_trace_writer_thread,
                     debug_trace, &tcb))
    goto failed;

  debug_trace->writer_thread_initialized = 1;

  ssh_task_start(&debug_trace->writer_thread);

  debug_trace->start_perf_cntr = 
    KeQueryPerformanceCounter(&debug_trace->perf_cntr_freq);

  /* Set the initial debug string */
  ssh_debug_set_level_string((const char *)debug_str);
  ssh_free(debug_str);

  ssh_registry_key_close(param_key);
  ssh_registry_key_close(conf_key);

  return debug_trace;

 disable_trace:
 failed:

  ssh_free(output_dir);
  ssh_free(debug_str);

  if (param_key)
    ssh_registry_key_close(param_key);

  if (conf_key)
    ssh_registry_key_close(conf_key);

  ssh_debug_trace_destroy(debug_trace);
  return NULL;
}


void
ssh_debug_trace_destroy(SshDebugTrace debug_trace)
{
  SshDebugMsg debug_msg;
  LIST_ENTRY *entry;

  if (!debug_trace)
    return;

  /* Terminate worker thread */
  if (debug_trace->writer_thread_initialized)
    {
      ssh_task_stop(&debug_trace->writer_thread);
      ssh_task_uninit(&debug_trace->writer_thread);
    }

  /* Flush remaining debug messages (if any) */
  while (!IsListEmpty(&debug_trace->list))
    {
      entry = RemoveHeadList(&debug_trace->list);
      debug_msg = CONTAINING_RECORD(entry, SshDebugMsgStruct, list_entry);

      if (debug_trace->handle)
        ssh_debug_trace_write_msg(debug_trace, debug_msg);

      ssh_free(debug_msg);
    }

  if (debug_trace->handle)
    ssh_file_close(debug_trace->handle);

  ssh_kernel_mutex_uninit(&debug_trace->lock);

  ssh_free(debug_trace);
}

void
ssh_debug_trace(SshDebugTrace debug_trace,
                const unsigned char *msg)
{
  SshDebugMsg debug_msg;

  if ((debug_trace == NULL) || (msg == NULL))
    return;

  if (debug_trace->bytes_left == 0)
    return;

  /* Notice that SshDebugMsg struct already has reserved space for 
     terminating NULL character */
  debug_msg = ssh_malloc(sizeof(*debug_msg) + ssh_ustrlen(msg));
  if (debug_msg == NULL)
    return;

  memcpy(debug_msg->msg, msg, ssh_ustrlen(msg) + 1);
  debug_msg->irql = SSH_GET_IRQL();
  ssh_debug_trace_timestamp(debug_trace, &debug_msg->ts_s, &debug_msg->ts_ns);
  ssh_kernel_mutex_lock(&debug_trace->lock);
  debug_msg->cpu = ssh_kernel_get_cpu();
  InitializeListHead(&debug_msg->list_entry);
  InsertTailList(&debug_trace->list, &debug_msg->list_entry);
  ssh_kernel_mutex_unlock(&debug_trace->lock);

  InterlockedIncrement(&debug_trace->msg_count);

  ssh_task_notify(&debug_trace->writer_thread, SSH_TASK_SIGNAL_NOTIFY);
}

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static void
ssh_debug_trace_timestamp(SshDebugTrace debug_trace,
                          SshTime *time_s,
                          SshUInt32 *time_ns)
{
  LARGE_INTEGER now;
  LARGE_INTEGER delta;

  now = KeQueryPerformanceCounter(NULL);

  delta.QuadPart = now.QuadPart - debug_trace->start_perf_cntr.QuadPart;

  *time_s = delta.QuadPart / debug_trace->perf_cntr_freq.QuadPart;

  delta.QuadPart -= *time_s * debug_trace->perf_cntr_freq.QuadPart;
  delta.QuadPart *= 1000000000UL;  /* convert to nanoseconds */

  *time_ns = 
    (SshUInt32)(delta.QuadPart / debug_trace->perf_cntr_freq.QuadPart);
}


static Boolean
ssh_debug_trace_write(SshDebugTrace debug_trace,
                      unsigned char *str)
{
  int len;

  if (debug_trace->handle == NULL)
    return FALSE;

  if (debug_trace->bytes_left == 0)
    return FALSE;

  len = ssh_ustrlen(str);

  if (debug_trace->bytes_left > (SshUInt64)len)
    {
      ssh_file_write(debug_trace->handle, str, len);
      debug_trace->bytes_left -= len;

      return  TRUE;
    }
  else
    {
      /* Maximum size of the trace reached; close the trace */
      debug_trace->bytes_left = 0;
      ssh_file_write(debug_trace->handle,
                     (void *)SSH_DEBUG_TRACE_FULL_TEXT,
                     ssh_ustrlen(SSH_DEBUG_TRACE_FULL_TEXT));

      ssh_file_close(debug_trace->handle);

      return FALSE;
    }
}


static Boolean
ssh_debug_trace_writeln(SshDebugTrace debug_trace,
                        unsigned char *str)
{
  if (ssh_debug_trace_write(debug_trace, str)
      && ssh_debug_trace_write(debug_trace, (unsigned char *)"\r\n"))
    return TRUE;
  else
    return FALSE;
}


static Boolean
ssh_debug_trace_write_msg(SshDebugTrace debug_trace,
                          SshDebugMsg debug_msg)
{
  Boolean success = TRUE;
  unsigned char temp[64];
  int len;

  len = ssh_snprintf(temp, sizeof(temp), "[%u;%u] %lu.%09lu  ", 
                     debug_msg->cpu, debug_msg->irql, 
                     (SshUInt32)debug_msg->ts_s, debug_msg->ts_ns);

  success &= ssh_debug_trace_write(debug_trace, temp);
  success &= ssh_debug_trace_writeln(debug_trace, debug_msg->msg); 

  return success;
}


static void
ssh_debug_trace_writer_thread(SshDebugTrace debug_trace)
{
  /* Create output file, if it haven't been created yet */
  if (debug_trace->handle == NULL)
    {
      debug_trace->handle = ssh_file_create(debug_trace->filename, TRUE);

      /* We can not create the file yet, retry later. (This can happen
         if the symbolic link (e.g. "C:") of the disk partition has not been 
         created yet) */
      if (debug_trace->handle == NULL)
        return;
    }

  /* Loop until the debug message queue is empty */
  while (debug_trace->handle)
    {
      SshDebugMsg debug_msg;
      LIST_ENTRY *entry;
 
      ssh_kernel_mutex_lock(&debug_trace->lock);
      if (IsListEmpty(&debug_trace->list))
        {
          ssh_kernel_mutex_unlock(&debug_trace->lock);
          break;
        }
      entry = RemoveHeadList(&debug_trace->list);
      ssh_kernel_mutex_unlock(&debug_trace->lock);

      debug_msg = CONTAINING_RECORD(entry, SshDebugMsgStruct, list_entry);

      ssh_debug_trace_write_msg(debug_trace, debug_msg);
      ssh_free(debug_msg);
      InterlockedDecrement(&debug_trace->msg_count);
    }
}


#endif /* DEBUG_LIGHT */



