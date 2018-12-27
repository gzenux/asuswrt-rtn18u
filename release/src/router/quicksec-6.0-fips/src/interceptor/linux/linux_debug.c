/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Debugging functions for interceptor. These functions are common to
   all Linux 2.x versions.
*/

#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorDebug"







/***************************** Module parameters ****************************/

#define SSH_INTERCEPTOR_DEBUG_MAX_LENGTH 300
static unsigned char *debug_msg_buf[SSH_LINUX_INTERCEPTOR_NR_CPUS] = { NULL };

/* Engine debug string. */
static char *engine_debug = NULL;
MODULE_PARM_DESC(engine_debug, "Engine debug level string.");
module_param(engine_debug, charp, 0444);

static int engine_debug_info = 0;
MODULE_PARM_DESC(engine_debug_info, "Debug timestamp and CPU information.");
module_param(engine_debug_info, int, 0444);

/***************************** Debug callbacks ******************************/

/* Called when fatal error occurs. */

void
ssh_kernel_fatal_callback(const char *buf, void *context)
{





  panic("%s\n", buf);
}

/* Called when warning occurs. */

void
ssh_kernel_warning_callback(const char *buf, void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
  const unsigned char *pbuf;
  SshTime time_now;
  SshUInt32 microseconds;

  if (interceptor == NULL)
    {
      ssh_kernel_fatal_callback(buf, context);
      return;
    }

  if (atomic_read(&interceptor->ipm.open) == 0 || interceptor->engine == NULL)
    {
      if (net_ratelimit())
        {
          if (engine_debug_info != 0)
            {
              ssh_interceptor_get_time(&time_now, &microseconds);
              printk(KERN_CRIT "[%u] %lu.%06lu %s\n", ssh_kernel_get_cpu(),
                     (unsigned long) time_now,
                     (unsigned long) microseconds, buf);
            }
          else
            {
              printk(KERN_CRIT "%s\n", buf);
            }
        }
      return;
    }

  /* Pass the message to the policy manager. */
  local_bh_disable();
  if (engine_debug_info != 0)
    {
      unsigned int cpu_ind = ssh_kernel_get_cpu();

      ssh_interceptor_get_time(&time_now, &microseconds);
      ssh_snprintf(debug_msg_buf[cpu_ind],
                   SSH_INTERCEPTOR_DEBUG_MAX_LENGTH,
                   "[%u] %lu.%06lu %s",
                   cpu_ind, (unsigned long)time_now,
                   microseconds, buf);

      pbuf = debug_msg_buf[cpu_ind];
    }
  else
    {
      pbuf = buf;
    }

  ssh_engine_send_warning(interceptor->engine, pbuf);
  local_bh_enable();

  return;
}

/* Called when debug message occurs. */

void
ssh_kernel_debug_callback(const char *buf, void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
  SshTime time_now;
  SshUInt32 microseconds;
  const unsigned char *pbuf;

  if (interceptor == NULL)
    {
      ssh_kernel_fatal_callback(buf, context);
      return;
    }

  if (atomic_read(&interceptor->ipm.open) == 0 || interceptor->engine == NULL)
    {
      if (net_ratelimit())
        {
          if (engine_debug_info != 0)
            {
              ssh_interceptor_get_time(&time_now, &microseconds);
              printk(KERN_CRIT "[%u] %lu.%06lu %s\n", ssh_kernel_get_cpu(),
                     (unsigned long) time_now,
                     (unsigned long) microseconds, buf);
            }
          else
            {
              printk(KERN_ERR "%s\n", buf);
            }
        }
      return;
    }

  local_bh_disable();
  if (engine_debug_info != 0)
    {
      unsigned int cpu_ind = ssh_kernel_get_cpu();

      ssh_interceptor_get_time(&time_now, &microseconds);
      ssh_snprintf(debug_msg_buf[cpu_ind],
                   SSH_INTERCEPTOR_DEBUG_MAX_LENGTH,
                   "[%u] %lu.%06lu %s",
                   cpu_ind, (unsigned long)time_now,
                   microseconds, buf);

      pbuf = debug_msg_buf[cpu_ind];
    }
  else
    {
      pbuf = buf;
    }

  ssh_engine_send_debug(interceptor->engine, pbuf);
  local_bh_enable();

  return;
}


/********************************** Init / Uninit ***************************/

size_t ssh_interceptor_get_debug_level(SshInterceptor interceptor,
                                       char *debug_string,
                                       size_t debug_string_len)
{
  return ssh_snprintf(debug_string, debug_string_len, "%s",
                      interceptor->debug_level_string);
}

void ssh_interceptor_set_debug_level(SshInterceptor interceptor,
                                     char *debug_string)
{
  ssh_snprintf(interceptor->debug_level_string,
               sizeof(interceptor->debug_level_string),
               "%s", debug_string);

  ssh_debug_set_level_string(interceptor->debug_level_string);
}

void ssh_interceptor_restore_debug_level(SshInterceptor interceptor)
{
  /* Restore debug level. */
  ssh_debug_set_level_string(interceptor->debug_level_string);
}

Boolean
ssh_interceptor_debug_init(SshInterceptor interceptor)
{
  int i;

  /* Setup debug callbacks. */
  ssh_debug_register_callbacks(ssh_kernel_fatal_callback,
                               ssh_kernel_warning_callback,
                               ssh_kernel_debug_callback,
                               interceptor);

  /* Set the default debugging level. */
  if (engine_debug != NULL)
    {
      printk(KERN_ERR "debug string: '%s'\n", engine_debug);
      ssh_snprintf(interceptor->debug_level_string,
                   sizeof(interceptor->debug_level_string),
                   "%s", engine_debug);
    }
  else
    {
      ssh_snprintf(interceptor->debug_level_string,
                   sizeof(interceptor->debug_level_string),
                   "*=0");
    }

  if (engine_debug_info != 0)
    {
      for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS; i++)
        {
          debug_msg_buf[i] = ssh_malloc(SSH_INTERCEPTOR_DEBUG_MAX_LENGTH);
          if (debug_msg_buf[i] == NULL)
            engine_debug_info = 0;
        }
    }

  ssh_debug_set_level_string(interceptor->debug_level_string);








  return TRUE;
}

void
ssh_interceptor_debug_uninit(SshInterceptor interceptor)
{
  int i;

  /* Uninitialize debug context (free memory) */
  ssh_debug_uninit();

  for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS; i++)
    {
      if (debug_msg_buf[i] != NULL)
        ssh_free(debug_msg_buf[i]);

      debug_msg_buf[i] = NULL;
    }





















}







































































































































































































