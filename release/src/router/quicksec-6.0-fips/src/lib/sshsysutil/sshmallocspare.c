/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Routines to handle spare buffers for malloc. There is N spare buffers
   allocated at all times and when mallocs fails it will call
   ssh_malloc_failed function that will free one those buffer and then
   malloc can retry allocation. Only when all spare buffers are gone then
   the ssh_malloc_failed will return actual error,
   which cause ssh_xmalloc etc to call fatal.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"

/* Note, these functions can be called from other threads also, thus
   cannot use any debugging macros (they can only be called from the
   SSH main thread).  Also note that you cannot call any other SSH
   library functions that are not marked thread safe from this file */
#undef SSH_DEBUG_MODULE
#ifdef malloc
# undef malloc
# undef calloc
# undef realloc
# undef free
# undef memdup
# undef strdup
#endif

#define SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS 16
SshMallocState ssh_malloc_current_state = SSH_MALLOC_STATE_NORMAL;
size_t ssh_malloc_total_spare_buffer_size = 0;
size_t ssh_malloc_spare_buffer_size = 0;
void *ssh_malloc_spare_buffers[SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS];

typedef struct SshMallocSignalFunctionListRec {
  struct SshMallocSignalFunctionListRec *next;
  SshMallocSignalFunction func;
  void *context;
} *SshMallocSignalFunctionList, SshMallocSignalFunctionListStruct;

SshMallocSignalFunctionList ssh_malloc_signal_functions = NULL;

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#ifdef ENABLE_VXWORKS_RESTART_WATCHDOG
void ssh_malloc_spare_restart(void)
{
  ssh_malloc_current_state = SSH_MALLOC_STATE_NORMAL;
  ssh_malloc_total_spare_buffer_size = 0;
  ssh_malloc_spare_buffer_size = 0;
  ssh_malloc_signal_functions = NULL;
}
#endif /* ENABLE_VXWORKS_RESTART_WATCHDOG */
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

/* Malloc failed, try freeing the spare buffers. Returns TRUE if some spare
   buffers were freed and we should try again with the original malloc. */
Boolean ssh_malloc_failed(void);

/* Register a signal function to allocation system. Signal functions will be
   called when there is a change in the memory allocation system status. */
void ssh_malloc_signal_function_register(SshMallocSignalFunction func,
                                         void *context)
{
  SshMallocSignalFunctionList item;

  ssh_malloc_failed_cb = ssh_malloc_failed;
 retry:

  if ((item = ssh_malloc(sizeof(*item))) != NULL)
    {
      item->next = ssh_malloc_signal_functions;
      item->func = func;
      item->context = context;
      ssh_malloc_signal_functions = item;
      return;
    }

  if (ssh_malloc_failed())
    goto retry;

  (*func)(SSH_MALLOC_STATE_MEMORY_CRITICAL, context);
}

/* Deregister signal function from the allocation function. After this call the
   signal function is no longer called. */
void ssh_malloc_signal_function_unregister(SshMallocSignalFunction func,
                                           void *context)
{
  SshMallocSignalFunctionList item, *prev_item;

  prev_item = &ssh_malloc_signal_functions;
  item = ssh_malloc_signal_functions;
  while (item)
    {
      if (item->func == func && item->context == context)
        {
          *prev_item = item->next;
          ssh_free(item);
          return;
        }
      prev_item = &item->next;
      item = *prev_item;
    }
}

/* Change state to given value if not already there. */
void ssh_malloc_change_state(SshMallocState new_state)
{
  SshMallocSignalFunctionList item;

  if (new_state == ssh_malloc_current_state)
    return;
  ssh_malloc_current_state = new_state;

  for (item = ssh_malloc_signal_functions; item; item = item->next)
    {
      (*item->func)(ssh_malloc_current_state, item->context);
    }
}

/* Try to regain spare buffers. */
void ssh_malloc_regain_spares(void *context)
{
  int i;

  for (i = 0; i < SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS; i++)
    {
      if (!ssh_malloc_spare_buffers[i])
        ssh_malloc_spare_buffers[i] = malloc(ssh_malloc_spare_buffer_size);
      if (ssh_malloc_spare_buffers[i] == NULL)
        {
          if (i == 0)
            ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_CRITICAL);
          else if (i <= SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS / 2)
            ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_LOW);
          break;
        }
    }
  if (i == SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS)
    {
      ssh_malloc_change_state(SSH_MALLOC_STATE_NORMAL);
    }
  else
    {
      ssh_cancel_timeouts(ssh_malloc_regain_spares, NULL);
      ssh_xregister_timeout(1, 0, ssh_malloc_regain_spares, NULL);
    }
}

/* Malloc failed, try freeing the spare buffers. Returns TRUE if some spare
   buffers were freed and we should try again with the original malloc. */
Boolean ssh_malloc_failed(void)
{
  int i;

  for (i = SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS - 1; i >= 0; i--)
    {
      if (ssh_malloc_spare_buffers[i])
        {
          free(ssh_malloc_spare_buffers[i]);
          ssh_malloc_spare_buffers[i] = NULL;
          if (i <= SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS / 4)
            ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_CRITICAL);
          else if (i <= SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS / 2)
            ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_LOW);
          ssh_cancel_timeouts(ssh_malloc_regain_spares, NULL);
          ssh_xregister_timeout(1, 0, ssh_malloc_regain_spares, NULL);
          return TRUE;
        }
    }
  return FALSE;
}

/* Change amount of spare buffers needed by the system. The signed 32 bit
   number is added to the size of the spare buffer. In the initialization this
   function is called with positive number that is the maximum amount of memory
   the subsystem needs to be able to work after the signal function is called.
   When the subsystem is uninitialized it must call this function with negative
   amount that lowers the spare buffer size by the amount it added there. One
   subsystem can call this function multiple times, i.e it can raise the amount
   of memory needed depending on the activity. */

void ssh_malloc_change_spare_buffer_size(SshInt32 change_in_bytes)
{
  int i;

  ssh_malloc_failed_cb = ssh_malloc_failed;

  if (change_in_bytes < 0 &&
      ssh_malloc_total_spare_buffer_size < -change_in_bytes)
    ssh_fatal("Ssh malloc spare buffer size goes to negative");
  ssh_malloc_total_spare_buffer_size += change_in_bytes;
  ssh_malloc_spare_buffer_size = ssh_malloc_total_spare_buffer_size * 2 /
    SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS;
  if (ssh_malloc_spare_buffer_size == 0)
    {
      for (i = 0; i < SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS; i++)
        {
          if (ssh_malloc_spare_buffers[i])
            free(ssh_malloc_spare_buffers[i]);
          ssh_malloc_spare_buffers[i] = NULL;
        }
    }
  else
    {
      for (i = 0; i < SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS; i++)
        {
          if (ssh_malloc_spare_buffers[i])
            ssh_malloc_spare_buffers[i] =
              realloc(ssh_malloc_spare_buffers[i],
                      ssh_malloc_spare_buffer_size);
          else
            ssh_malloc_spare_buffers[i] = malloc(ssh_malloc_spare_buffer_size);
          if (ssh_malloc_spare_buffers[i] == NULL)
            {
              if (i == 0)
                ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_CRITICAL);
              else if (i <= SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS / 2)
                ssh_malloc_change_state(SSH_MALLOC_STATE_MEMORY_LOW);
              break;
            }
        }
      if (i == SSH_MALLOC_NUMBER_OF_SPARE_BUFFERS)
        {
          ssh_malloc_change_state(SSH_MALLOC_STATE_NORMAL);
        }
    }
}

/* Return the current state of the memory allocation system. This can be used
   to select suitable algorithms depending if you have lots of memory of if you
   are almost running out of the memory. */
SshMallocState ssh_malloc_get_state(void)
{
  return ssh_malloc_current_state;
}
