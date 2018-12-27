/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of engine communication character device for VxWorks.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include <sshincludes.h>

#define SSH_DEBUG_MODULE "IceptChardevVxworks"

#include <iosLib.h>
#include <netLib.h>
#include <logLib.h>
#include <selectLib.h>
#include <engine.h>
#include <kernel_encode.h>
#include <sshgetput.h>
#include "icept_vxworks.h"
#include "icept_chardev.h"

/*
 * Misc. comments
 *
 * this code assumes that sizeof(int)==sizeof(void*) just as
 * VxWorks does. if VxWorks ever becomes 64-bit interfaces
 * of iosLib/netLib shall probably change too.
 *
 * this device assumes only one task is using it, therefore there
 * can't be multiple simultaneous read/write/open/close/ioctl
 * requests.
 *
 * When virtual stacks are enabled, one devices is configured per
 * virtual stack.
 */


/*
 * order of sensible execution:
 * 1. register device driver
 * 2. create device
 * 3. open a file corresponding to engine
 * 4. support select
 * 5. get read/write request
 * 6. process or make thread pend
 * 7. get notification of processing completed
 * 8. unblock thread
 * 9. get file closed
 * 10. possibly repeat from step 3
 */

#ifdef VIRTUAL_STACK
#else /* VIRTUAL_STACK */
#define SSH_DEV_NAME "/ipsec"
#endif /* VIRTUAL_STACK */

#define SSH_KERNEL_IPM_QUEUE_SIZE 256

struct SshKernelQueueRec
{
  Boolean reliable;
  unsigned char* data;
  size_t len;
};

/*
 * DEV_HDR must be first, because VxWorks expects pointer to our
 * structure to reference DEV_HDR.
 */
typedef struct SshDevRec
{
  DEV_HDR header;
  SEL_WAKEUP_LIST select_list;
  Boolean open;
  /* other stuff */
} SshDev;

#ifdef VIRTUAL_STACK
typedef struct SshDevDataRec
{
  struct SshDevDataRec *next;
  SshDev sddr_ssh_dev;
  SEM_ID sddr_queue_semaphore;
  int sddr_driver_number;
  struct SshKernelQueueRec sddr_ssh_ipm_queue[SSH_KERNEL_IPM_QUEUE_SIZE];
  int sddr_ssh_ipm_queue_len;
  int sddr_ssh_ipm_queue_byte_offset;
  const void *sddr_machine_context;
  unsigned int open_cnt;
  unsigned int close_cnt;
  unsigned int read_cnt;
  unsigned int write_cnt;
  unsigned int ioctl_cnt;
} *SshDevData;

SshDevData ssh_dev_recs;

/* Macros to access data via current ssh_dev_rec. */
#define SDDR_FROM_DEV(dev) \
  SshDevData ssh_dev_rec = ssh_sddr_dev(dev)
#define SDDR_FROM_MACHINE_CONTEXT(mc) \
  SshDevData ssh_dev_rec = ssh_sddr_mc(mc)

static SshDevData ssh_sddr_dev(SshDev *ssh_dev_ptr)
{
  SshDevData sdd = ssh_dev_recs;
  while (sdd)
    {
      if (&(sdd->sddr_ssh_dev) == ssh_dev_ptr)
	return sdd;

      sdd = sdd->next;
    }
  return NULL;
}

static SshDevData ssh_sddr_mc(const void *machine_context)
{
  SshDevData sdd = ssh_dev_recs;
  /* First try pointer match */
  while (sdd)
    {
      if (sdd->sddr_machine_context == machine_context)
	return sdd;

      sdd = sdd->next;
    }
  sdd = ssh_dev_recs;
  /* Maybe wild card? */
  if (!machine_context) return sdd;
  /* String match? */
  while (sdd)
    {
      if (!strcmp(sdd->sddr_machine_context, machine_context))
	return sdd;

      sdd = sdd->next;
    }
  /* No match */
  return NULL;
}

/* Macros to access data via current ssh_dev_rec. */
#define ssh_dev (ssh_dev_rec->sddr_ssh_dev)
#define queue_semaphore (ssh_dev_rec->sddr_queue_semaphore)
#define driver_number (ssh_dev_rec->sddr_driver_number)
#define ssh_ipm_queue (ssh_dev_rec->sddr_ssh_ipm_queue)
#define ssh_ipm_queue_len (ssh_dev_rec->sddr_ssh_ipm_queue_len)
#define ssh_ipm_queue_byte_offset (ssh_dev_rec->sddr_ssh_ipm_queue_byte_offset)

#else /* VIRTUAL_STACK */
static SshDev ssh_dev;
int ssh_dev_cnt;

#define SDDR_FROM_DEV(dev) do{}while(0)
#define SDDR_FROM_MACHINE_CONTEXT(mc) do{}while(0)

/* binary semaphore for synchronising addition of messages to queue
   with reading them out. */
static SEM_ID queue_semaphore;

static int driver_number = ERROR;

/* the queue, number of slots used and offset in the first message */
static struct SshKernelQueueRec ssh_ipm_queue[SSH_KERNEL_IPM_QUEUE_SIZE];
static int ssh_ipm_queue_len;
static int ssh_ipm_queue_byte_offset;
#endif /* VIRTUAL_STACK */

/* counters for tracking the number of pending netJob messages */
/* Notice: these must be global even when virtual stacks are present,
   therefore these aren't inside chardev structure. */
static unsigned ssh_netjobs_submitted;  /* updated by the ipm task */
static unsigned ssh_netjobs_processed; /* updated by tNetTask */
/* max difference of the counters above */
#define SSH_NETJOBS_MAX 20


/*
 * naming conventions... (none for now)
 * throughout this file, let's use "dev" as a name for this module.
 * it can be changed later anyway
 */


static int
  ssh_dev_open(DEV_HDR* device, char* filename_remainder, int mode);
static int
  ssh_dev_close(DEV_HDR* header);
static int
  ssh_dev_read( DEV_HDR* header, char * buffer, int length);
static int
  ssh_dev_write(DEV_HDR* header, char * buffer, int length);
static int
  ssh_dev_ioctl(DEV_HDR* header, int request, int arg);

struct ssh_message_from_ipm
{
  SshEngine engine;
  int type;
  unsigned char* buffer;
  size_t length;
};

static void
  ssh_send_packet_from_ipm(int arg1, int arg2, int arg3, int arg4, int arg5);


int ssh_vx_dev_init(const char *devname)
{
  STATUS status;
#ifdef VIRTUAL_STACK
  SshDevData ssh_dev_rec = ssh_malloc(sizeof(struct SshDevDataRec));

  if (!ssh_dev_rec)
{
      SSH_DEBUG(SSH_D_ERROR,
		("driver install failed: unable to allocate memory"));
      return 1;
    }
#endif /* VIRTUAL_STACK */

  driver_number = iosDrvInstall((FUNCPTR) 0 /* no create */,
                                (FUNCPTR) 0 /* no remove */,
                                (FUNCPTR) ssh_dev_open,
                                (FUNCPTR) ssh_dev_close,
                                (FUNCPTR) ssh_dev_read,
                                (FUNCPTR) ssh_dev_write,
                                (FUNCPTR) ssh_dev_ioctl );

  if (driver_number == ERROR)
  {
#ifdef VIRTUAL_STACK
    ssh_free(ssh_dev_rec);
#endif /* VIRTUAL_STACK */
    SSH_DEBUG(SSH_D_ERROR, ("driver install failed"));
    return 1;
  }

  selWakeupListInit(&ssh_dev.select_list);
  ssh_dev.open = FALSE;
  /* there can be only one or no tasks blocked on this semaphore */
  queue_semaphore = semBCreate(SEM_Q_FIFO, SEM_FULL);
  ssh_ipm_queue_len = 0;
  ssh_ipm_queue_byte_offset = 0;

#ifndef SSH_DEV_NAME
  status = iosDevAdd ( (DEV_HDR*) &ssh_dev, devname, driver_number);
#else /* !SSH_DEV_NAME */
  status = iosDevAdd ( (DEV_HDR*) &ssh_dev, SSH_DEV_NAME, driver_number);
#endif /* !SSH_DEV_NAME */
  if (status!=OK)
  {
    logMsg("Error: device \"%s\" addition failed\n",
#ifndef SSH_DEV_NAME
	   (int)devname,
#else /* !SSH_DEV_NAME */
	   (int)SSH_DEV_NAME,
#endif /* !SSH_DEV_NAME */
	   0,0,0,0,0);
    status = iosDrvRemove(driver_number, TRUE);
    driver_number = ERROR;
    if (status!=OK)
      logMsg("Error: driver *removal* failed!!!\n",0,0,0,0,0,0);
#ifdef VIRTUAL_STACK
    ssh_free(ssh_dev_rec);
#endif /* VIRTUAL_STACK */
    return 1;
  }

#ifdef VIRTUAL_STACK
  ssh_dev_rec->next = ssh_dev_recs;
  ssh_dev_rec->sddr_machine_context = devname;
  ssh_dev_recs = ssh_dev_rec;
#else /* VIRTUAL_STACK */
  ssh_dev_cnt++;
#endif /* VIRTUAL_STACK */
  return 0;
}


int ssh_vx_dev_uninit(const char *devname)
{
  int ret = TRUE;
#ifdef VIRTUAL_STACK
  SshDevData sdd_prev = (SshDevData)&ssh_dev_recs;
#endif /* VIRTUAL_STACK */
  SDDR_FROM_MACHINE_CONTEXT(devname);

#ifdef VIRTUAL_STACK
  if (devname == NULL) ssh_dev_rec = ssh_dev_recs;

  if (ssh_dev_rec == NULL)
    {
      logMsg("Error: No such ssh interceptor to destroy.\n",0,0,0,0,0,0);
      return FALSE;
    }

  if (ssh_dev_rec->open_cnt > ssh_dev_rec->close_cnt)
    {
      logMsg("Error: Refusing closing interceptor %p that is open: %d "
	     "refs.\n",
	     (int)ssh_dev_rec,
	     (int)ssh_dev_rec->open_cnt-ssh_dev_rec->close_cnt,0,0,0,0);
      return FALSE;
    }
#else /* VIRTUAL_STACK */
  if (ssh_dev_cnt == 0)
{
      logMsg("Error: No more ssh interceptors to destroy.\n",0,0,0,0,0,0);
      return FALSE;
    }
#endif /* VIRTUAL_STACK */

#ifdef VIRTUAL_STACK
  while (sdd_prev->next != ssh_dev_rec) sdd_prev = sdd_prev->next;
#endif /* VIRTUAL_STACK */

  if (driver_number == ERROR)
  {
    logMsg("Error: driver_number is an ERROR!\n",0,0,0,0,0,0);
    return FALSE;
  }

  semDelete(queue_semaphore);

  if (ssh_ipm_queue_len != 0 || ssh_ipm_queue_byte_offset != 0)
  {
    logMsg("Error: queue isn't cleared at ssh_vx_dev_uninit!\n",0,0,0,0,0,0);
  }

  iosDevDelete((DEV_HDR*) &ssh_dev);

  if (OK != iosDrvRemove(driver_number, FALSE))
  {
    logMsg("Error: ncie removal failed, forcing",0,0,0,0,0,0);
    if (OK != iosDrvRemove(driver_number, TRUE))
      logMsg("Error: forced removal failed",0,0,0,0,0,0);
  }

  /* Remove all if wildcard given. */
#ifdef VIRTUAL_STACK
  if (!devname && ssh_dev_recs)
    ret = ssh_vx_dev_uninit(NULL);

  sdd_prev->next = ssh_dev_rec->next;
  ssh_free(ssh_dev_rec);
#else /* VIRTUAL_STACK */
  ssh_dev_cnt--;
#endif /* VIRTUAL_STACK */
  return ret;
}


/* The machine-specific main program should call this when the policy
   manager has opened the connection to the engine.  This also
   sends the version packet to the policy manager.  This function signals
   semaphore after ssh_engine_notify_ipm_open() has been executed. */
void ssh_engine_notify_ipm_open_vx(SshEngine engine, SEMAPHORE *sem, int i3,
                                   int i4, int i5)
{
  ssh_engine_notify_ipm_open(engine);
  semGive(sem);
}

/* The machine-specific main program should call this when the policy
   manager has closed the connection to the engine. This function can
   be called concurrently with packet/interface callbacks or timeouts. */
void ssh_engine_notify_ipm_close_vx(SshEngine engine, SEMAPHORE *sem, int i3,
                                    int i4, int i5)
{

  ssh_engine_notify_ipm_close(engine);
  semGive(sem);
}


/*
 * xx_open function returns an int which is supplied to subsequent
 * xx_read|write|ioctl|close as first argument. Since there can be
 * only one file descriptor opened for ipsec device, We'll reuse
 * address of entry in device table ssh_dev as entry in file
 * descriptor table. Thus we get same first argument in xx_open and
 * xx_read|write|ioctl|close routines.
 */


int ssh_dev_open(DEV_HDR* device, char* filename_remainder, int mode)
{
  SEMAPHORE *ssh_engine_notify_ipm_open_wait;
  SshDev* dev = (SshDev*) device;
#ifdef VIRTUAL_STACK
  SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */
  SDDR_FROM_DEV(dev);

#ifdef VIRTUAL_STACK
  if (!ssh_dev_rec)
    return ERROR;

  ssh_engine =
    SSH_ENGINE_BY_MACHINE_CONTEXT(ssh_dev_rec->sddr_machine_context);
#endif /* VIRTUAL_STACK */

  /* insist on filename having no remainder */
  if (filename_remainder!=NULL)
    if (*filename_remainder!=(char)0)
      return ERROR;

  if (dev->open)
    return EBUSY;




  dev->open = TRUE;

#ifdef VIRTUAL_STACK
  SSH_DEBUG(SSH_D_NICETOKNOW, ("chardev, engine is %x: dev=%p:%p, ctx=%p:%s",
  			       (int)ssh_engine,
  			       device, &ssh_dev,
			       ssh_dev_rec,
			       ssh_dev_rec->sddr_machine_context));
#else /* VIRTUAL_STACK */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("chardev, engine is %x: dev=%p:%p",
                (int)ssh_engine,
  			       device, &ssh_dev));
#endif /* VIRTUAL_STACK */

  ssh_engine_notify_ipm_open_wait = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  semTake(ssh_engine_notify_ipm_open_wait, WAIT_FOREVER);

  if (netJobAdd((FUNCPTR)ssh_engine_notify_ipm_open_vx,
                (int)ssh_engine,
                (int)ssh_engine_notify_ipm_open_wait,0,0,0) != OK)
    ssh_warning("ssh_dev_open: netJobAdd failed");

  semTake(ssh_engine_notify_ipm_open_wait, WAIT_FOREVER);
  semDelete(ssh_engine_notify_ipm_open_wait);
  /* return "identifier", pointer to the device structure */
#ifdef VIRTUAL_STACK
  ssh_dev_rec->open_cnt++;
#endif /* VIRTUAL_STACK */
  return (int)device;
}

int ssh_dev_close(DEV_HDR* header)
{
  SEMAPHORE *ssh_engine_notify_ipm_close_wait;
#ifdef VIRTUAL_STACK
  SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */
  SDDR_FROM_DEV((SshDev*)header);

#ifdef VIRTUAL_STACK
  if (!ssh_dev_rec)
    return ERROR;

  ssh_engine =
    SSH_ENGINE_BY_MACHINE_CONTEXT(ssh_dev_rec->sddr_machine_context);
#endif /* VIRTUAL_STACK */

  /* sink all pending messages */
  semTake(queue_semaphore, WAIT_FOREVER);
  ssh_ipm_queue_byte_offset = 0;
  while (ssh_ipm_queue_len > 0)
  {
    ssh_ipm_queue_len--;
    ssh_free(ssh_ipm_queue[ssh_ipm_queue_len].data);
  }
  semGive(queue_semaphore);

#ifdef VIRTUAL_STACK
  ssh_dev_rec->close_cnt++;
#endif /* VIRTUAL_STACK */

  ssh_engine_notify_ipm_close_wait = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  semTake(ssh_engine_notify_ipm_close_wait, WAIT_FOREVER);

  /* notify the engine */
  if (netJobAdd((FUNCPTR)ssh_engine_notify_ipm_close_vx,
                (int)ssh_engine,
                (int)ssh_engine_notify_ipm_close_wait,0,0,0) != OK)
    ssh_warning("ssh_dev_close: netJobAdd failed");

  semTake(ssh_engine_notify_ipm_close_wait, WAIT_FOREVER);
  semDelete(ssh_engine_notify_ipm_close_wait);

  ((SshDev*)header)->open = FALSE;

  return 0;
}

int ssh_dev_read( DEV_HDR* header, char * buffer, int length)
{
  int rv=0;
  int read=0;
  int i;
#ifdef VIRTUAL_STACK
  SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */
  SDDR_FROM_DEV((SshDev*)header);

#ifdef VIRTUAL_STACK
  if (!ssh_dev_rec)
    return ERROR;

  ssh_engine =
    SSH_ENGINE_BY_MACHINE_CONTEXT(ssh_dev_rec->sddr_machine_context);
#endif /* VIRTUAL_STACK */

  if (!((SshDev*)header)->open)
    SSH_DEBUG(SSH_D_ERROR, ("shouldn't get read calls here"));

#ifdef VIRTUAL_STACK
  ssh_dev_rec->read_cnt++;
#endif /* VIRTUAL_STACK */

  semTake(queue_semaphore, WAIT_FOREVER);
  /* read packets out */
  for (;;)
  {
    SSH_ASSERT(length >= rv);
    if (length == rv) break;

    SSH_ASSERT(ssh_ipm_queue_len >= read);
    if (read == ssh_ipm_queue_len) break;

    SSH_ASSERT(ssh_ipm_queue[read].len > ssh_ipm_queue_byte_offset);

    if (ssh_ipm_queue[read].len - ssh_ipm_queue_byte_offset > length - rv)
    {
      /* there's more data in this buffer than requested */
      memcpy(buffer + rv,
            ssh_ipm_queue[read].data + ssh_ipm_queue_byte_offset,
            length - rv);
      ssh_ipm_queue_byte_offset += length - rv;
      rv  += length - rv;
    }
    else
    {
      /* more (or exact amount of) data is requested than there is in
         the current buffer */

      memcpy(buffer + rv,
            ssh_ipm_queue[read].data + ssh_ipm_queue_byte_offset,
            ssh_ipm_queue[read].len - ssh_ipm_queue_byte_offset);
      rv  += ssh_ipm_queue[read].len - ssh_ipm_queue_byte_offset;
      ssh_ipm_queue_byte_offset = 0;
      read++;
    }
  }

  SSH_ASSERT(read <= SSH_KERNEL_IPM_QUEUE_SIZE);
  /* now, first 'read' number of buffers were read, free them */
  for (i=0; i<read; i++)
    {
      ssh_free(ssh_ipm_queue[i].data);
    }

  if (read)
  {
    memmove(ssh_ipm_queue, ssh_ipm_queue + read,
            sizeof(*ssh_ipm_queue) * (ssh_ipm_queue_len - read));
    ssh_ipm_queue_len -= read;
  }
  semGive(queue_semaphore);

  if (rv > 0)
    return rv;

  errno = EAGAIN;
  return -1;
}

/* unfortunately there's no provision to check if there's space in
   tNetTask work queue beforehands or get notified of space there.
   therefore it's possible that PM will write only 0 (zero) bytes,
   and since writes never block, PM might end up in a loop where it
   attempts to write on the device and cannot, whereas fd is marked
   "ready to be written to" by select.

   Therefore, in order not to exhaust work queue of tNetTask, it's
   priority should be higher than task of PM.
 */
int ssh_dev_write(DEV_HDR* header, char * buffer, int length)
{
  struct ssh_message_from_ipm* msg;
  int type;
  size_t p_len;
  int pos = 0;
  STATUS st;
  int messages = 0;
#ifdef VIRTUAL_STACK
  SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */
  SDDR_FROM_DEV((SshDev*)header);

#ifdef VIRTUAL_STACK
  if (!ssh_dev_rec)
    return ERROR;

  ssh_engine =
    SSH_ENGINE_BY_MACHINE_CONTEXT(ssh_dev_rec->sddr_machine_context);
#endif /* VIRTUAL_STACK */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("chardev: write: header=%p <%p:%d",
			       header, buffer, length));

#ifdef VIRTUAL_STACK
  ssh_dev_rec->write_cnt++;
#endif /* VIRTUAL_STACK */

  /*
   * divide data in packets
   * add em as work queue entries to tNetTask
   */
  for (;;)
  {
    SSH_ASSERT(pos <= length);

    if (pos == length) return pos; /* processed all messages */

    /* stop writing if too many messages pending */
    if (ssh_netjobs_submitted - ssh_netjobs_processed >= SSH_NETJOBS_MAX)
      {
	/* delay one clock tick to allow tNetTask to run in case
	   current task is more prioritized and is repeatedly calling
	   write() */
	taskDelay(1);
	goto incomplete_write;
      }

    /* check that header (length+type) is present */
    if (length < pos + 5)
    {
      SSH_DEBUG(SSH_D_ERROR, ("format error, truncated header"));
      errno = 0;



      return pos;  /* or -1 ? */
    }

    p_len = SSH_GET_32BIT(buffer + pos);
    type  = SSH_GET_8BIT(buffer + pos + 4);

    if (pos + 4 + p_len > length)
    {
      SSH_DEBUG(SSH_D_ERROR, ("format error, truncated data"));
      errno = 0;



      return pos;



    }

    msg = ssh_malloc(sizeof(*msg));
    if (!msg)
      goto incomplete_write;

    msg->engine = ssh_engine;
    msg->type = type;
    msg->length = p_len - 1; /* excluding type byte */
    msg->buffer = ssh_malloc(msg->length);

    if (!msg->buffer)
      {
	ssh_free(msg);
	goto incomplete_write;
      }

    /* copy the data */
    memcpy(msg->buffer, buffer + pos + 5, msg->length);
    st = netJobAdd( (FUNCPTR)ssh_send_packet_from_ipm, (int)msg, 0, 0, 0, 0 );
    if (st != OK)
      {
	ssh_free(msg->buffer);
	ssh_free(msg);
	goto incomplete_write;
      }

    ssh_netjobs_submitted++;

    /* length + (type + data) */
    pos += 4 + p_len;
    messages++;
  }

  /* not reached */
  return 0;

 incomplete_write:
  if (pos == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("wrote zero"));
      errno = EAGAIN;
      return -1;
    }
  else
    return pos;
}

int ssh_dev_ioctl(DEV_HDR* header, int request, int arg)
{
  SshDev* dev = (SshDev*)header;
  Boolean wakeup;
  SDDR_FROM_DEV((SshDev*)header);

#ifdef VIRTUAL_STACK
  ssh_dev_rec->ioctl_cnt++;
#endif /* VIRTUAL_STACK */

  switch(request)
  {
    case FIOSELECT:
      {
        SEL_WAKEUP_NODE* node = (SEL_WAKEUP_NODE*) arg;

        selNodeAdd(&dev->select_list, node);

        if (selWakeupType(node) == SELREAD)
        {
          semTake(queue_semaphore, WAIT_FOREVER);
          wakeup = (ssh_ipm_queue_len != 0);
          semGive(queue_semaphore);
          if (wakeup) selWakeup(node);
        }
        else if (selWakeupType(node) == SELWRITE)
        {




          /* there seems to be no way to check if data could really
             be netJodAdd()-ed, thus, neither if it can be written */
          selWakeup(node);
        }
        break;
      }
    case FIOUNSELECT:
      {
        SEL_WAKEUP_NODE* node = (SEL_WAKEUP_NODE*) arg;
        selNodeDelete(&dev->select_list, node);
        break;
      }
    case FIONBIO:
      {
        /* we are always non-blocking that's what ssh code sets */
        if (*(int*) arg == 1)
        {
          /* OK */
        }
        else if (*(int*) arg == 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("attempted to set blocking behaviour"));
          errno = EINVAL; return -1;
        }
        else
        {
          /* unknown value */;
          errno = EINVAL; return -1;
        }
        break;
      }
    default:
      {
        errno = EINVAL; return -1;
      }
  }
  return OK;
}

Boolean ssh_send_to_ipm(unsigned char* data, size_t len,
			Boolean reliable, void* machine_context)
{
  Boolean rv;
  signed int i;
  /* changes if we store 1st msg in the queue */
  Boolean wakeup = FALSE;
  SDDR_FROM_MACHINE_CONTEXT(machine_context);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_send_to_ipm: %p:%d r=%d, dev=%p:%s",
			       data, len, reliable,
			       machine_context,
			       machine_context?
			       machine_context : "(null)"));

  /* lock queue */
  semTake(queue_semaphore, WAIT_FOREVER);

  if (!ssh_dev.open)
  {
    rv = FALSE;
    goto done;
  }

  SSH_ASSERT(ssh_ipm_queue_len <= SSH_KERNEL_IPM_QUEUE_SIZE);

  wakeup = (ssh_ipm_queue_len == 0 && SSH_KERNEL_IPM_QUEUE_SIZE != 0);
  if (ssh_ipm_queue_len == SSH_KERNEL_IPM_QUEUE_SIZE)
  {
    if (!reliable)
    {
      SSH_DEBUG(SSH_D_ERROR, ("dropped unreliable message"));
      rv = FALSE;
      goto done;
    }
    /* we are supposed to overwrite some unreliable message */
    /* we'll do so to the last of them */
    for (i = ssh_ipm_queue_len - 1; i >= 0; i--)
    {
      /* let's find an unreliable victim */
      if (ssh_ipm_queue[i].reliable) continue;

      /* we can't cancel message, part of which has already been
         read out */
      if (i == 0 && ssh_ipm_queue_byte_offset != 0) continue;

      SSH_DEBUG(SSH_D_ERROR, ("dropping unreliable message at index %d", i));
      ssh_free(ssh_ipm_queue[i].data);

      /* messages should be delivered FIFO whether reliable or not */
      memmove(ssh_ipm_queue + i, ssh_ipm_queue + i + 1,
              sizeof(*ssh_ipm_queue) * (ssh_ipm_queue_len - i - 1));

      ssh_ipm_queue[ssh_ipm_queue_len - 1].reliable = reliable;
      ssh_ipm_queue[ssh_ipm_queue_len - 1].data = data;
      ssh_ipm_queue[ssh_ipm_queue_len - 1].len = len;
      rv = TRUE;
      goto done;
    }
    SSH_DEBUG(SSH_D_ERROR, ("dropping a reliable message!"));
    rv = FALSE;
    goto done;
  }
  else
  {
    ssh_ipm_queue[ssh_ipm_queue_len].reliable = reliable;
    ssh_ipm_queue[ssh_ipm_queue_len].data = data;
    ssh_ipm_queue[ssh_ipm_queue_len].len = len;

    ssh_ipm_queue_len++;
    rv = TRUE;
    goto done;
  }


done:

  /* unlock queue */
  semGive(queue_semaphore);

  /* we are supposed to free 'data' */
  if (!rv) ssh_free(data);

  /* hmmm, maybe this needs to be inside semTake|Give ... */
  if (wakeup) selWakeupAll(&ssh_dev.select_list, SELREAD);
  return rv;
}

void ssh_send_packet_from_ipm(int arg1, int arg2, int arg3, int arg4, int arg5)
{
#ifdef VIRTUAL_STACK
  SshVxEngine vxe;
#endif /* VIRTUAL_STACK */
  struct ssh_message_from_ipm* msg = (struct ssh_message_from_ipm *) arg1;

  ssh_netjobs_processed++;

  /* check that engine still exists */
#ifdef VIRTUAL_STACK
  vxe = ssh_engines;
  while (vxe)
    {
      if (vxe->engine == msg->engine) break;
      vxe = vxe->next;
    }
  if (!vxe) return;
#else /* VIRTUAL_STACK */
  if (NULL == ssh_engine || msg->engine != ssh_engine) return;
#endif /* VIRTUAL_STACK */

  ssh_engine_packet_from_ipm(msg->engine, msg->type,
                              msg->buffer, msg->length);
  ssh_free(msg->buffer);
  ssh_free(msg);
}

#ifdef DEBUG_LIGHT
void ssh_dev_dump(void)
{
#ifdef VIRTUAL_STACK
  SshDevData ssh_dev_rec = ssh_dev_recs;
  while (ssh_dev_rec)
    {
#endif /* VIRTUAL_STACK */

      printf("Device: %p mc=%p:%s drv=%d sema=%p qlen=%d\n",
	     &ssh_dev,
#ifdef SSH_DEV_NAME
	     SSH_DEV_NAME,
#else /* SSH_DEV_NAME */
	     (const char*) (ssh_dev_rec->sddr_machine_context),
#endif /* SSH_DEV_NAME */
#ifdef SSH_DEV_NAME
	     SSH_DEV_NAME,
#else /* SSH_DEV_NAME */
	     (const char*) (ssh_dev_rec->sddr_machine_context),
#endif /* SSH_DEV_NAME */
	     driver_number, queue_semaphore, ssh_ipm_queue_len);

#ifdef VIRTUAL_STACK
      printf("  Statistics: open=%u close=%u read=%u write=%u ioctl=%u\n",
	     ssh_dev_rec->open_cnt,
	     ssh_dev_rec->close_cnt,
	     ssh_dev_rec->read_cnt,
	     ssh_dev_rec->write_cnt,
	     ssh_dev_rec->ioctl_cnt);
      ssh_dev_rec = ssh_dev_rec->next;
    }
#endif /* VIRTUAL_STACK */
}

#endif /* DEBUG_LIGHT */
