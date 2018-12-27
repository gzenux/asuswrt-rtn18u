/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel-mode interface to the policy manager using a character device.
   The kernel-mode ipsec is designed to run entirely at ssh_interceptor_spl.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#include "sshincludes.h"
#include "ipsec_params.h"
#include "kernel_encode.h"
#include "sshgetput.h"
#include "engine.h"
#include "icept_chardev.h"
#include "icept_internal.h"
#include <sys/kernel.h>

#define SSH_DEBUG_MODULE "IceptKernelMain"

#define SSH_KERNEL_IPM_MAX_PACKET_SIZE  (256*1024)
#define SSH_KERNEL_IPM_QUEUE_SIZE       512

static Boolean ipforwarding_revert_on_close;
static int ipforwarding_saved;
extern int ipforwarding;

/* Name of the device used to communicate with the kernel-mode IPSEC
   Engine. */
const char *ssh_device_name = "/dev/quicksec";

SshEngine ssh_engine = NULL;

typedef struct SshKernelQueueRec
{
  Boolean reliable;
  unsigned char *data;
  size_t len;
  size_t offset;
} SshKernelQueue;

/* Number of entries in the queue. */
unsigned int ssh_ipm_queue_len = 0;

/* The queue entries.  Only the slots in the beginning of the array
   are used. */
SshKernelQueue ssh_ipm_queue[SSH_KERNEL_IPM_QUEUE_SIZE];

size_t ssh_ipm_residual = 0;
size_t ssh_ipm_offset;
unsigned char ssh_ipm_lentype[5];
unsigned char *ssh_ipm_buf = NULL;

/* This is called whenever the device is opened.  This returns
   errno, or 0 on successs. */

int ssh_chardev_open()
{
  int s;

  if (!ssh_engine)
    {
      printf("ssh_chardev_open: engine not open\n");
      return EIO;
    }

  /* Notify the IPSEC Engine that the policy manager connection has been
     opened. */
  s = ssh_interceptor_spl();

  ipforwarding_revert_on_close = FALSE;
  ipforwarding_saved = ipforwarding;

  ssh_engine_notify_ipm_open(ssh_engine);
  splx(s);
  return 0;
}

/* This is called when the interceptor is closed for the last time (since
   we only one process to have it open at a time, this means whenever it
   is closed). */

void ssh_chardev_close()
{
  int s, i;

  if (!ssh_engine)
    {
      printf("ssh_chardev_close: engine not open\n");
      return;
    }

  if (ipforwarding_revert_on_close)
    {
      printf("reverting to old ipforwarding (%d)", ipforwarding_saved);
      ipforwarding = ipforwarding_saved;
    }

  /* Notify the IPSEC Engine that the policy manager connection has
     been closed. */
  s = ssh_interceptor_spl();
  ssh_engine_notify_ipm_close(ssh_engine);

  /* Free the send queue and the buffer used for writes. */
  for (i = 0; i < ssh_ipm_queue_len; i++)
    ssh_free(ssh_ipm_queue[i].data);
  ssh_ipm_queue_len = 0;
  ssh_ipm_residual = 0;
  ssh_free(ssh_ipm_buf);
  ssh_ipm_buf = NULL;
  splx(s);
}

/* Read entry point.  This returns packets wrapped into a header as suggested
   in the interceptor document.  This always returns full packets; if a
   packet does not fit in the buffer, part of it is lost. */

int ssh_chardev_read(void *io_context, size_t max_len)
{
  SshKernelQueue *qe;
  size_t len;
  int error, s;

  s = ssh_interceptor_spl();

  /* If we have data, copy some data into the user buffer. */
  if (ssh_ipm_queue_len > 0)
    {
      qe = &ssh_ipm_queue[0];
      len = qe->len - qe->offset;
      if (len > max_len)
        len = max_len;
      error = ssh_chardev_io_transfer(qe->data + qe->offset, len, io_context);
      if (error)
        {
          splx(s);
          return error;
        }
      qe->offset += len;
      if (qe->offset >= qe->len)
        {
          ssh_free(qe->data);
          ssh_ipm_queue_len--;
          memmove(&ssh_ipm_queue[0], &ssh_ipm_queue[1],
                  ssh_ipm_queue_len * sizeof(ssh_ipm_queue[0]));
        }
    }
  splx(s);
  return 0;
}

/* This is the write entry point for the device.  The written data contains
   one or more packets to send out (to the network or to protocols).
   Packets must always be sent with a single write.  Sending multiple packets
   with a single write is allowed. */

int ssh_chardev_write(void *io_context, size_t max_len)
{
  unsigned char *ucp;
  int error, s;
  size_t len;

  s = ssh_interceptor_spl();

  /* Loop until all written data processed. */
  while (ssh_chardev_io_residual(io_context) > 0)
    {
      /* If at start of packet, set to read in length and type first. */
      if (ssh_ipm_residual == 0)
        {
          ssh_ipm_residual = 5;
          ssh_ipm_offset = 0;
          SSH_ASSERT(ssh_ipm_buf == NULL);
        }

      /* Loop while packet not fully read and data available. */
      while (ssh_ipm_residual > 0 && ssh_chardev_io_residual(io_context) > 0)
        {
          /* Determine where to read (header buffer vs. packet data). */
          if (ssh_ipm_offset < 5)
            ucp = ssh_ipm_lentype + ssh_ipm_offset;
          else
            {
              SSH_ASSERT(ssh_ipm_buf != NULL);
              ucp = ssh_ipm_buf + ssh_ipm_offset - 5;
            }

          /* Compute the number of bytes to transfer. */
          len = ssh_chardev_io_residual(io_context);
          if (len > ssh_ipm_residual)
            len = ssh_ipm_residual;
          SSH_ASSERT(len > 0);

          /* Transfer some data into our buffer. */
          error = ssh_chardev_io_transfer(ucp, len, io_context);
          if (error)
            {
              splx(s);
              return error;
            }
          ssh_ipm_offset += len;
          ssh_ipm_residual -= len;

          /* If done with the header, allocate space for packet data. */
          if (ssh_ipm_offset == 5 && ssh_ipm_residual == 0)
            {
              ssh_ipm_residual = SSH_GET_32BIT(ssh_ipm_lentype);
              if (ssh_ipm_residual <= 0 ||
                  ssh_ipm_residual >= SSH_KERNEL_IPM_MAX_PACKET_SIZE)
                {
                  printf("malformed packet from PM: len=%d, type=%d\n",
                         ssh_ipm_residual, ssh_ipm_lentype[4]);
                  ssh_ipm_residual = 0;
                  splx(s);
                  return EIO;
                }
              ssh_ipm_residual--;
              SSH_ASSERT(ssh_ipm_buf == NULL);
              ssh_ipm_buf = ssh_malloc(ssh_ipm_residual);
              if (ssh_ipm_buf == NULL)
                /*  */
                ssh_fatal("Could not allocate memory for PM's packet");
            }
        }
      if (ssh_ipm_residual > 0)
        break;

      /* Process the packet from ipm. */
      ssh_engine_packet_from_ipm(ssh_engine, ssh_ipm_lentype[4],
                                 ssh_ipm_buf, ssh_ipm_offset - 5);

      /* Free dynamically allocated data. */
      ssh_free(ssh_ipm_buf);
      ssh_ipm_buf = NULL;
    }
  splx(s);
  return 0;
}

/* This function should return non-zero if data is available for reading, and
   0 if no data is currently available for reading. */

int ssh_chardev_read_available()
{
  int s, ret;

  s = ssh_interceptor_spl();
  ret = ssh_ipm_queue_len > 0;
  splx(s);

  return ret;
}

/* This function should return non-zero if data can be written to the device,
   and 0 if no data can currently be written to the device (e.g., buffers
   are full). */

int ssh_chardev_write_available()
{
  return 1;
}

#if defined(__NetBSD__)
unsigned long ssh_since_last_report = 0;
long ssh_last_time = 0;
#endif /* __NetBSD__ */

/* Attempts to send the message to the policy manager.  This returns TRUE
   if the message was actually sent, and FALSE otherwise.  This frees
   `data' using ssh_free in either case.  `data' should start with a
   32-bit MSB first packet length and a 1-byte type field. */

Boolean ssh_send_to_ipm(unsigned char *data, size_t len,
                        Boolean reliable, void *machine_context)
{
  SshKernelQueue *qe;
  unsigned int i;

  /* WARNING: This is called from the ssh_debug callback, which means
     that no debug functions can be called here, or we'll end up in
     infinite recursion! */

  /* Check if the policy manager connection is open. */
  if (!ssh_chardev_is_open)
    {
      ssh_free(data);
      return FALSE;
    }

  /* Check if there is space in the queue. */
  if (ssh_ipm_queue_len >= SSH_KERNEL_IPM_QUEUE_SIZE)
    {
      if (!reliable)
        {
#if defined(__NetBSD__)
	  struct timeval cur_time;
#if SSH_NetBSD < 400
	  cur_time = time;
#else /* SSH_NetBSD < 400 */
	  getmicrotime(&cur_time);
#endif /* SSH_NetBSD < 400 */

     if (cur_time.tv_sec - ssh_last_time < 2)
            {
              ssh_since_last_report++;
            }
          else
            {
              if (ssh_since_last_report == 0)
                printf("ssh_send_to_ipm: queue full, message dropped\n");
              else
                printf("ssh_send_to_ipm: queue full, %ld messages dropped\n",
                       ssh_since_last_report + 1);
              ssh_since_last_report = 0;
              ssh_last_time = cur_time.tv_sec;
            }
#else  /* __NetBSD__ */
          printf("ssh_send_to_ipm: queue full, message dropped\n");
#endif /* __NetBSD__ */
          ssh_free(data);
          return FALSE;
        }
      /* The new message is reliable.  Throw away some non-reliable message
         already in the queue.  The first entry is never removed, as it
         might be partially sent already. */
      for (i = ssh_ipm_queue_len - 1; i > 0; i--)
        if (!ssh_ipm_queue[i].reliable)
          {
            /* Remove this entry from the queue. */
            printf("ssh_send_to_ipm: dropping entry to make space "
                   "for important packet\n");
            ssh_free(ssh_ipm_queue[i].data);
            memmove(&ssh_ipm_queue[i], &ssh_ipm_queue[i + 1],
                    (ssh_ipm_queue_len - i - 1) * sizeof(ssh_ipm_queue[0]));
            ssh_ipm_queue_len--;
            break;
          }
      if (ssh_ipm_queue_len >= SSH_KERNEL_IPM_QUEUE_SIZE)
        {
          printf("ssh_send_to_ipm: WARNING: queue full, "
                 "important packet dropped\n");
          ssh_free(data);
          return FALSE;
        }
    }

  /*  reliable sends should always be queued! */

  /* Queue the packet. */
  qe = &ssh_ipm_queue[ssh_ipm_queue_len++];
  qe->reliable = reliable;
  qe->offset = 0;
  qe->data = data;
  qe->len = len;

  /* Wake up the character device. */
  ssh_chardev_wakeup();
  return TRUE;
}

void ssh_kernel_fatal_cb(const char *message, void *context)
{
  panic(message);
}

void ssh_kernel_warning_cb(const char *message, void *context)
{
  printf("SSH IPSEC Warning: %s\n", message);
  if (ssh_engine != NULL)
    ssh_engine_send_warning(ssh_engine, message);
}

void ssh_kernel_debug_cb(const char *message, void *context)
{
  /* WARNING: this function cannot call SSH_DEBUG functions or it will
     end up in infinite recursion! */
#if 1
  if (ssh_engine != NULL)
    {
#if 0
      printf("%s\n", message);
#endif
      ssh_engine_send_debug(ssh_engine, message);
    }
  else
#endif
    printf("%s\n", message);
}

/* This function is called when the kernel module has been loaded. This
   should initialize kernel code above the interceptor, if any. */

void ssh_upper_initialize(void)
{
  int s;

  s = ssh_interceptor_spl();

  /* Register callbacks for the debugging functions. */
  ssh_debug_register_callbacks(ssh_kernel_fatal_cb,
                               ssh_kernel_warning_cb,
                               ssh_kernel_debug_cb,
                               NULL);

#if 0
  /* Set verbose debugging as default.  This code is only useful during
     basic debugging.  It should not be enabled for normal operation. */
  ssh_debug_set_level_string("*=9");
#endif

  /* Initialize the IPSEC Engine.  If the SSH_ENGINE_DROP_IF_NO_IPM
     flag is passed to the engine, the engine will drop all packets if
     the policy manager is not connected to the engine.  The default
     flags are 0 just to ease debugging.  This should be set to
     appropriate value when the system is compiled to production
     use. */
  SSH_ASSERT(ssh_engine == NULL);
  ssh_engine = ssh_engine_start(ssh_send_to_ipm, NULL,
				SSH_IPSEC_ENGINE_FLAGS);

  splx(s);
}

/* This function is called when the kernel module is being unloaded. This
   should uninitialize kernel code above the interceptor, if any. */

void ssh_upper_uninitialize(void)
{
  int s;
  Boolean first = TRUE;

  s = ssh_interceptor_spl();
  if (ssh_engine)
    {
      while (!ssh_engine_stop(ssh_engine))
        {
          if (first)
            {
              printf("ssh_upper_uninitialize looping...\n");
              first = FALSE;
            }
          /*  should do a context switch... */
        }
      ssh_engine = NULL;
    }








  splx(s);
}
