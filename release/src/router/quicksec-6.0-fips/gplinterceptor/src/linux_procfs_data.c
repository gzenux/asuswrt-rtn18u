/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Procfs frontend for Linux interceptor.
*/

#include "linux_internal.h"
#include <linux/wait.h>
#include <linux/uio.h>

#define SSH_DEBUG_MODULE "SshInterceptorUsercommData"

#define LINUX_PROCFS_DATA_READ_PACKETS_MAX 10

extern SshInterceptor ssh_interceptor_context;

/************************ Internal utility functions ************************/

/* Use printk instead of SSH_DEBUG macros. */
#ifdef DEBUG_LIGHT
#define SSH_LINUX_UD_DEBUG(x...) if (net_ratelimit()) printk(KERN_INFO x)
#define SSH_LINUX_UD_WARN(x...) printk(KERN_EMERG x)
#endif /* DEBUG_LIGHT */

#ifndef SSH_LINUX_UD_DEBUG
#define SSH_LINUX_UD_DEBUG(x...)
#define SSH_LINUX_UD_WARN(x...)
#endif /* SSH_LINUX_UD_DEBUG */

#define SSH_PACKET_IDATA_FLAGS_OFFSET          sizeof(SshUInt32)
#define SSH_PACKET_IDATA_IFNUM_IN_OFFSET       (2 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_IFNUM_OUT_OFFSET      (3 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_RIID_OFFSET           (4 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_PROTO_OFFSET          (5 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_INTERNAL_LEN_OFFSET   (6 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_INTERNAL_DATA_OFFSET  (7 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_HEADER_LEN            (8 * sizeof(SshUInt32))


static int
interceptor_ud_read_block(
        SshInterceptor interceptor)
{
      /* Blocking mode, sleep until a message or a signal arrives. */
#ifdef LINUX_USE_WAIT_EVENT
  wait_event_interruptible(interceptor->ud_proc_entry.wait_queue,
                               interceptor_ud_proc_entry_read_allowed(
                                                             interceptor));
#else /* LINUX_USE_WAIT_EVENT */
  interruptible_sleep_on(&interceptor->ud_proc_entry.wait_queue);
#endif /* LINUX_USE_WAIT_EVENT */

  if (signal_pending(current))
    {
      SSH_LINUX_UD_DEBUG("interceptor_userdata_proc_entry_fop_read: "
                         "-ERESTARTSYS\n");
      return -ERESTARTSYS;
    }

  return 0;
}


static int
interceptor_packet_get_queue_length(
        SshInterceptorPacket pp)
{
    return
        SSH_PACKET_IDATA_HEADER_LEN +
        ssh_interceptor_packet_internal_data_length(pp) +
        ssh_interceptor_packet_len(pp);
}

void interceptor_ud_message_free(SshInterceptor interceptor,
                                 SshInterceptorPacket pp)
{
  local_bh_disable();
  write_lock(&interceptor->ipm.lock);

  /* Free packet buffer */
  ssh_interceptor_packet_free(pp);

  write_unlock(&interceptor->ipm.lock);
  local_bh_enable();
}

/************************ Userdata proc entry *********************************/

Boolean ssh_interceptor_ud_init(SshInterceptor interceptor)
{
  /* Initialize ud structure */
  atomic_set(&interceptor->ud.open, 0);
  rwlock_init(&interceptor->ud.lock);

  interceptor->ud.send_queue = NULL;
  interceptor->ud.send_queue_tail = NULL;

  /* Initialize /proc interface */
 if (interceptor_userdata_proc_entry_init(interceptor) == FALSE)
    goto error;

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Could not create /proc entry for data"));
  interceptor_userdata_proc_entry_uninit(interceptor);

  return FALSE;
}

void ssh_interceptor_ud_uninit(SshInterceptor interceptor)
{
  /* Enable softirqs. */
  local_bh_enable();

  interceptor_userdata_proc_entry_uninit(interceptor);

 /* Disable softirqs. */
  local_bh_disable();
}

void interceptor_ud_open(SshInterceptor interceptor)
{

  local_bh_disable();
  write_lock(&interceptor->ud.lock);

  /* Assert that send queue is empty */
  SSH_ASSERT(interceptor->ud.send_queue == NULL);

  /* Mark ipm channel open */
  atomic_set(&interceptor->ud.open, 1);

  write_unlock(&interceptor->ud.lock);
  local_bh_enable();
}

void interceptor_ud_close(SshInterceptor interceptor)
{
  SshInterceptorPacket list, msg;

  local_bh_disable();
  write_lock(&interceptor->ud.lock);

  /* Mark data channel closed */
  atomic_set(&interceptor->ud.open, 0);

  /* Clear send queue */
  list = interceptor->ud.send_queue;
  interceptor->ud.send_queue = NULL;
  interceptor->ud.send_queue_tail = NULL;
  interceptor->ud.in_queue_cnt = 0;
  interceptor->ud.in_queue_bytes = 0;

  write_unlock(&interceptor->ud.lock);
  local_bh_enable();

  /* Free all data messages from send queue. */
  while (list != NULL)
    {
      msg = list;
      list = msg->next;
      interceptor_ud_message_free(interceptor, msg);
    }
}

static void
interceptor_ud_send_queue_insert(
        SshInterceptorPacket pp)
{
  pp->next = NULL;
  if (ssh_interceptor_context->ud.send_queue == NULL)
    {
      ssh_interceptor_context->ud.send_queue = pp;
      ssh_interceptor_context->ud.send_queue_tail = pp;
    }
  else
    {
      ssh_interceptor_context->ud.send_queue_tail->next = pp;
      ssh_interceptor_context->ud.send_queue_tail = pp;
    }

  ssh_interceptor_context->ud.in_queue_cnt++;
  ssh_interceptor_context->ud.in_queue_bytes +=
      interceptor_packet_get_queue_length(pp);

}

static SshInterceptorPacket
interceptor_ud_send_queue_first(
        void)
{
    return ssh_interceptor_context->ud.send_queue;
}

static void
interceptor_ud_send_queue_remove_first(
        void)
{
  SshInterceptorPacket pp = ssh_interceptor_context->ud.send_queue;

  SSH_ASSERT(pp != NULL);

  ssh_interceptor_context->ud.send_queue = pp->next;

  if (pp->next == NULL)
    {
      ssh_interceptor_context->ud.send_queue_tail = NULL;
    }

  pp->next = NULL;

  SSH_ASSERT(ssh_interceptor_context->ud.in_queue_cnt > 0);
  SSH_ASSERT(ssh_interceptor_context->ud.in_queue_bytes > 0);

  ssh_interceptor_context->ud.in_queue_cnt--;
  ssh_interceptor_context->ud.in_queue_bytes -=
      interceptor_packet_get_queue_length(pp);
}


void ssh_interceptor_ud_send(SshInterceptorPacket pp)
{
  local_bh_disable();
  write_lock(&ssh_interceptor_context->ud.lock);

  /* Check ipm channel status */
  if (atomic_read(&ssh_interceptor_context->ud.open) == 0)
    {
      write_unlock(&ssh_interceptor_context->ud.lock);
      local_bh_enable();
      ssh_interceptor_packet_free(pp);
      SSH_LINUX_UD_DEBUG("UD channel closed, dropping message\n");
      return;
    }

  interceptor_ud_send_queue_insert(pp);

  write_unlock(&ssh_interceptor_context->ud.lock);
  local_bh_enable();

  /* Wake up reader. */
  wake_up_interruptible(&ssh_interceptor_context->ud_proc_entry.wait_queue);

  return;
}

#ifdef LINUX_USE_WAIT_EVENT
static Boolean
interceptor_userdata_proc_entry_read_allowed(SshInterceptor interceptor)
{
  Boolean ret = FALSE;

  local_bh_disable();
  write_lock(&interceptor->ud.lock);

  if (interceptor->ud.send_queue != NULL)
    ret = TRUE;

  write_unlock(&interceptor->ud.lock);
  local_bh_enable();

  return ret;
}
#endif /* LINUX_USE_WAIT_EVENT */

#define UD_MAX_TO_READ 4

int
interceptor_ud_copy_user(
        char __user *buf,
        size_t len,
        SshInterceptorPacket pp)
{
  unsigned char headerbuf[256];
  int header_len;
  unsigned char *internal_data;
  int packet_len;
  size_t internal_len = 0;

  const int packet_buf_len = interceptor_packet_get_queue_length(pp);

  if (len < packet_buf_len)
    {
      return -EMSGSIZE;
    }

  SSH_PUT_32BIT(headerbuf, 0); /* read_out == total packets read ? */
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_FLAGS_OFFSET, pp->flags);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_IFNUM_IN_OFFSET, pp->ifnum_in);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_IFNUM_OUT_OFFSET, pp->ifnum_out);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_RIID_OFFSET, (SshUInt32) 0);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_PROTO_OFFSET, pp->protocol);

  if (!ssh_interceptor_packet_export_internal_data(pp,
                                                   &internal_data,
                                                   &internal_len))
    {
      SSH_LINUX_UD_WARN("interceptor_userdata_proc_entry_fop_read: "
                        "retrieving internal data failed, dropping message\n");
      return -EFAULT;
    }

  memcpy(headerbuf + SSH_PACKET_IDATA_INTERNAL_DATA_OFFSET,
         internal_data, internal_len);
  ssh_free(internal_data);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_INTERNAL_LEN_OFFSET,
                internal_len);
  packet_len = ssh_interceptor_packet_len(pp);
  SSH_PUT_32BIT(headerbuf + SSH_PACKET_IDATA_INTERNAL_DATA_OFFSET +
                internal_len, packet_len);

  header_len = SSH_PACKET_IDATA_HEADER_LEN + internal_len;

  if (copy_to_user(buf, headerbuf, header_len))
    {
      SSH_LINUX_UD_WARN("interceptor_userdata_proc_entry_fop_read: "
                            "copy_to_user failed, dropping message\n");
      return -EFAULT;
    }


    {
      SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
      struct iovec uio;

      uio.iov_base = buf + header_len;
      uio.iov_len = len - header_len;

      if (skb_copy_datagram_iovec(ipp->skb, 0, &uio, packet_len))
        {

          SSH_LINUX_UD_WARN("interceptor_userdata_proc_entry_fop_read: "
                            "copy_to_user failed, dropping message\n");
          return -EFAULT;
        }
    }

  SSH_ASSERT(packet_buf_len ==
             packet_len + SSH_PACKET_IDATA_HEADER_LEN + internal_len);

  return packet_buf_len;
}


static int
interceptor_ud_read_begin(void)
{
  SshInterceptor interceptor = (void *) ssh_interceptor_context;

  write_lock(&interceptor->ud_proc_entry.lock);


  if (interceptor->ud_proc_entry.read_active)
   {
      write_unlock(&interceptor->ud_proc_entry.lock);
      SSH_LINUX_UD_DEBUG("interceptor_userdata_proc_entry_fop_read:"
                             " -EBUSY\n");
      return -EBUSY;
    }

  interceptor->ud_proc_entry.read_active = TRUE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  return 0;
}

static void
interceptor_ud_read_end(void)
{
  SshInterceptor interceptor = (void *) ssh_interceptor_context;

  write_lock(&interceptor->ud_proc_entry.lock);

  SSH_ASSERT(interceptor->ud_proc_entry.read_active == TRUE);

  interceptor->ud_proc_entry.read_active = FALSE;

  write_unlock(&interceptor->ud_proc_entry.lock);
}

static ssize_t
interceptor_userdata_proc_entry_fop_read(struct file *file,
                                         char __user *buf,
                                         size_t len,
                                         loff_t *pos)
{
  SshInterceptor interceptor = file->private_data;

  SshInterceptorPacket pp = NULL;
  int offset = 0;
  int result = 0;
  int packet_count;

  result = interceptor_ud_read_begin();
  if (result != 0)
    {
      return result;
    }

  while (result == 0 && pp == NULL)
    {
      local_bh_disable();
      write_lock(&interceptor->ud.lock);

      pp = interceptor_ud_send_queue_first();

      write_unlock(&interceptor->ud.lock);
      local_bh_enable();

      if (pp == NULL)
        {
          if (file->f_flags & O_NONBLOCK)
            {
              result = -EAGAIN;
            }
          else
            {
              result = interceptor_ud_read_block(interceptor);
            }
        }
    }

  packet_count = 0;
  while (result == 0 && pp != NULL &&
	 packet_count < LINUX_PROCFS_DATA_READ_PACKETS_MAX)
    {
      SshInterceptorPacket new_packet;
      int copied;

      ++packet_count;

      copied = interceptor_ud_copy_user(buf + offset, len - offset, pp);
      if (copied < 0)
        {
          result = copied;
	  if (result == -EMSGSIZE && offset != 0)
	    {
	      pp = NULL;
	      result = 0;
	    }
        }
      else
        {
          local_bh_disable();
          write_lock(&interceptor->ud.lock);
  
          interceptor_ud_send_queue_remove_first();

          new_packet = interceptor_ud_send_queue_first();

          write_unlock(&interceptor->ud.lock);
          local_bh_enable();

          interceptor_ud_message_free(interceptor, pp);

          pp = new_packet;

          offset += copied;
        }
    }

  if (result == 0)
    {
      result = offset;
    }

  interceptor_ud_read_end();

  return result;
}


#ifdef LINUX_USE_WAIT_EVENT
static Boolean
interceptor_userdata_proc_entry_write_allowed(SshInterceptor interceptor)
{
  Boolean ret = TRUE;

  write_lock(&interceptor->ud_proc_entry.lock);
  if (interceptor->ud_proc_entry.write_active == TRUE)
    ret = FALSE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  return ret;
}
#endif /* LINUX_USE_WAIT_EVENT */

static ssize_t
interceptor_userdata_proc_entry_fop_write(struct file *file,
                                          const char __user *buf,
                                          size_t len,
                                          loff_t *pos)
{
  size_t offset = 0;
  SshInterceptor interceptor = file->private_data;

  /* Limit the maximum write length to avoid running in softirq
     context for long periods of time. */
  if (len > sizeof(interceptor->ud_proc_entry.rcvbuf))
    {
      return -EINVAL;
    }

 retry:
  /* Check if there is another write going on. */
  write_lock(&interceptor->ud_proc_entry.lock);
  if (interceptor->ud_proc_entry.write_active)
    {
      write_unlock(&interceptor->ud_proc_entry.lock);

      /* Non-blocking mode, fail write. */
      if (file->f_flags & O_NONBLOCK)
        {
          return -EAGAIN;
        }
      /* Blocking mode, wait until other writes are done. */
#ifdef LINUX_USE_WAIT_EVENT
      wait_event_interruptible(interceptor->ud_proc_entry.wait_queue,
                               interceptor_ud_proc_entry_write_allowed(
                                                                interceptor));
#else /* LINUX_USE_WAIT_EVENT */
      interruptible_sleep_on(&interceptor->ud_proc_entry.wait_queue);
#endif /* LINUX_USE_WAIT_EVENT */

      if (signal_pending(current))
        {
          SSH_LINUX_UD_DEBUG("interceptor_userdata_proc_entry_fop_write: "
                             "-ERESTARTSYS\n");
          return -ERESTARTSYS;
        }

      goto retry;
    }

  interceptor->ud_proc_entry.write_active = TRUE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  /* Let's take a peek how many packets there are... */
  while (offset < len)
    {
      /* Indicate the packet... */
      offset += ssh_engine_from_ipm_user_data_packet(interceptor->engine,
						     buf + offset,
						     len - offset);
      if (offset < 0)
	{
	  break;
	}
    }

  write_lock(&interceptor->ud_proc_entry.lock);
  interceptor->ud_proc_entry.write_active = FALSE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  return offset;
}

static unsigned int
interceptor_userdata_proc_entry_fop_poll(struct file *file,
                                         struct poll_table_struct *table)
{
  unsigned int mask = 0;
  SshInterceptor interceptor = file->private_data;

  poll_wait(file, &interceptor->ud_proc_entry.wait_queue, table);

  local_bh_disable();
  read_lock(&interceptor->ud.lock);

  /* Check if there is a message pending for sending. */
  if (interceptor->ud.send_queue != NULL &&
      interceptor->ud.in_queue_cnt > 0)
    mask |= (POLLIN | POLLRDNORM);

  /* Always writable... */
  mask |= (POLLOUT | POLLWRNORM);

  read_unlock(&interceptor->ud.lock);
  local_bh_enable();

  return mask;
}

static int
interceptor_userdata_proc_entry_fop_open(struct inode *inode,
                                         struct file *file)
{
  write_lock(&ssh_interceptor_context->ud_proc_entry.lock);

  if (ssh_interceptor_context->ud_proc_entry.open)
    {
      write_unlock(&ssh_interceptor_context->ud_proc_entry.lock);
      SSH_LINUX_UD_DEBUG("interceptor_userdata_proc_entry_fop_open:"
                             " -EBUSY\n");
      return -EBUSY;
    }

  file->private_data = ssh_interceptor_context;

  ssh_interceptor_context->ud_proc_entry.open = TRUE;

  /* Clear receive buffer. */
  ssh_interceptor_context->ud_proc_entry.recv_len = 0;

  write_unlock(&ssh_interceptor_context->ud_proc_entry.lock);

  interceptor_ud_open(ssh_interceptor_context);

  return 0;
}

static int
interceptor_userdata_proc_entry_fop_release(struct inode *inode,
                                            struct file *file)
{
  SshInterceptor interceptor = file->private_data;
  SshInterceptorIpmMsg msg;

  /* Mark data channel closed and clear send queue */
  interceptor_ud_close(interceptor);

  write_lock(&interceptor->ud_proc_entry.lock);
  interceptor->ud_proc_entry.open = FALSE;

  /* Clear receive buffer. */
  interceptor->ipm_proc_entry.recv_len = 0;

  /* Get rid of unsent packets... */
  msg = interceptor->ud_proc_entry.send_msg;
  interceptor->ud_proc_entry.send_msg = NULL;

  write_unlock(&interceptor->ud_proc_entry.lock);

  if (msg)
    ssh_free(msg);

  return 0;
}

/* Creates and initializes the procfs entry */
static struct proc_dir_entry *
interceptor_create_procfs_entry(const char* name, umode_t mode,
                                struct proc_dir_entry *parent,
                                struct file_operations *fops)
{
  struct proc_dir_entry *pde = NULL;

#ifdef LINUX_HAS_PROC_CREATE_DATA
  pde = proc_create_data(name, mode, parent, fops, NULL);
  /* fops cannot be null for this case */
#else /* LINUX_HAS_PROC_CREATE_DATA */
  pde = create_proc_entry(name, mode, parent);
  if (pde == NULL)
    return NULL;
  /* Set ops to NULL so that the entries cannot be used until later, when
  ssh_interceptor_proc_enable() is called */
  pde->proc_fops = NULL;
  pde->proc_iops = NULL;
#endif /* LINUX_HAS_PROC_CREATE_DATA */

  if (pde == NULL)
    return NULL;

#ifdef LINUX_HAS_PROC_DIR_ENTRY_OWNER
  pde->owner = THIS_MODULE;
#endif

#ifdef LINUX_HAS_PROC_SET_FUNCTIONS
  proc_set_size(pde, 0);
  proc_set_user(pde, KUIDT_INIT(0), KGIDT_INIT(0));
#else  /* LINUX_HAS_PROC_SET_FUNCTIONS */
  pde->uid = 0;
  pde->gid = 0;
  pde->size = 0;
#endif /* LINUX_HAS_PROC_SET_FUNCTIONS */

  return pde;
}

static struct file_operations userdata_proc_entry_fops =
{
  .read = interceptor_userdata_proc_entry_fop_read,
  .write = interceptor_userdata_proc_entry_fop_write,
  .poll = interceptor_userdata_proc_entry_fop_poll,
  .open = interceptor_userdata_proc_entry_fop_open,
  .release = interceptor_userdata_proc_entry_fop_release
};

Boolean
interceptor_userdata_proc_entry_init(SshInterceptor interceptor)
{
  /* Assert that parent dir exists. */
  SSH_ASSERT(interceptor->proc_dir != NULL);

  /* Initialize proc entry structure. */
  init_waitqueue_head(&interceptor->ud_proc_entry.wait_queue);
  rwlock_init(&interceptor->ud_proc_entry.lock);

  write_lock(&interceptor->ud_proc_entry.lock);
  interceptor->ud_proc_entry.open = TRUE;
  interceptor->ud_proc_entry.write_active = TRUE;

  interceptor->ud_proc_entry.read_active = TRUE;
  interceptor->ud_proc_entry.enabled = FALSE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  /* Create entry to procfs. */
  interceptor->ud_proc_entry.entry =
    interceptor_create_procfs_entry(SSH_PROC_DATA,
                                    S_IFREG | S_IRUSR | S_IWUSR,
                                    interceptor->proc_dir,
                                    &userdata_proc_entry_fops);
  if (interceptor->ud_proc_entry.entry == NULL)
    return FALSE;

  /* Mark proc entry ready for use. */
  write_lock(&interceptor->ud_proc_entry.lock);
  interceptor->ud_proc_entry.open = FALSE;
  interceptor->ud_proc_entry.write_active = FALSE;
  interceptor->ud_proc_entry.read_active = FALSE;
  write_unlock(&interceptor->ud_proc_entry.lock);

  return TRUE;
}

void
interceptor_userdata_proc_entry_uninit(SshInterceptor interceptor)
{
  if (interceptor->ud_proc_entry.entry != NULL)
    PROC_REMOVE(interceptor->ud_proc_entry.entry, interceptor->proc_dir);
  write_lock(&interceptor->ud_proc_entry.lock);
  interceptor->ud_proc_entry.entry = NULL;
  interceptor->ud_proc_entry.enabled = FALSE;
  write_unlock(&interceptor->ud_proc_entry.lock);
}
