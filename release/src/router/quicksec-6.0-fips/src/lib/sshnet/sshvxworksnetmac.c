/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VxWorks implementation of the sshnetmac.h API.
*/

#include "sshincludes.h"
#include "sshnetmac.h"
#include "sshnetconfig.h"
#include "ssheloop.h"

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS

#include <endLib.h>
#include <muxLib.h>
#include <etherLib.h>
#include <ioLib.h>
#include <iosLib.h>
#include <selectLib.h>
#include <netBufLib.h>

#define SSH_DEBUG_MODULE "SshVxworksNetmac"

/*
 * Types.
 */

typedef struct {
  /* buffer full bit */
  volatile unsigned rdy;
  /* frame contents */
  unsigned char buf[1518];
  /* frame length */
  unsigned len;
} SshVxworksNetmacBufferStruct;

struct SshNetmacHandleRec
{
  /* device header, must be first */
  DEV_HDR dev;
  /* select() queue */
  SEL_WAKEUP_LIST dev_swl;
  /* device name, e.g. "/netmac/fei0" */
  char dev_name[32];
  /* nonzero if device added to system */
  int dev_added;
  /* file descriptor */
  int dev_fd;
  /* nonzero if dev_fd registered in the event loop */
  int dev_registered;
  /* nonzero if the device is opened and not closed */
  int dev_open;
  /* nonzero if the device can be read() */
  int dev_readable;
  /* receive parameters */
  SshUInt16 proto;
  SshNetmacReceiveCallback receive_callback;
  void *receive_context;
  /* cookie returned by muxBind() */
  void *cookie;
  /* receive frame ring buffer */
  SshVxworksNetmacBufferStruct rxring[4];
  /* ring input and output indexes */
  unsigned rxring_in;
  unsigned rxring_out;
};

/*
 * Prototypes.
 */

static
void netmac_io_callback(unsigned int events, void *context);

static int
netmac_open(SshNetmacHandle h, char *name, int mode);

static int
netmac_close(SshNetmacHandle h);

static int
netmac_read(SshNetmacHandle h, char *buf, size_t len);

static int
netmac_ioctl(SshNetmacHandle h, int cmd, int arg);

static BOOL
netmac_receive(
  void *cookie, long type, M_BLK_ID m, LL_HDR_INFO *ll, void *spare);

static STATUS
netmac_shutdown(void *cookie, void *spare);

static STATUS
netmac_restart(void *cookie, void *spare);

static void
netmac_error(END_OBJ *end, END_ERR *err, void *spare);

/*
 * Static data.
 */

/* device driver number */
static int netmac_drv_num;

/* count of created devices */
static int netmac_dev_cnt;

/*
 * Public functions.
 */

SshNetconfigError
ssh_netmac_send(SshNetmacHandle h,
                const unsigned char *dst,
                const unsigned char *src,
                const unsigned char *data_buf,
                size_t data_len)
{
  M_BLK_ID mblk;
  struct enet_hdr *hdr;

  mblk =
    netTupleGet(
      _pNetSysPool, sizeof *hdr + data_len, M_DONTWAIT, MT_DATA, FALSE);

  if (!mblk)
    return SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;

  if (mblk->pClBlk->clSize < sizeof *hdr + data_len)
    {
      netMblkClChainFree(mblk);
      return SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
    }

  hdr = (void *)mblk->mBlkHdr.mData;
  memcpy(hdr->dst, dst, sizeof hdr->dst);
  memcpy(hdr->src, src, sizeof hdr->src);
  hdr->type = htons(h->proto);
  memcpy(mblk->mBlkHdr.mData + sizeof *hdr, data_buf, data_len);
  mblk->mBlkHdr.mLen = sizeof *hdr + data_len;

  mblk->mBlkHdr.mFlags |= M_PKTHDR;
  mblk->mBlkPktHdr.len = mblk->mBlkHdr.mLen;

  SSH_DEBUG(
    SSH_D_LOWOK,
    ("Sending MAC frame, "
     "dst %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
     "src %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
     "length/type 0x%04.4X, data length %u",
     (unsigned)hdr->dst[0], (unsigned)hdr->dst[1], (unsigned)hdr->dst[2],
     (unsigned)hdr->dst[3], (unsigned)hdr->dst[4], (unsigned)hdr->dst[5],
     (unsigned)hdr->src[0], (unsigned)hdr->src[1], (unsigned)hdr->src[2],
     (unsigned)hdr->src[3], (unsigned)hdr->src[4], (unsigned)hdr->src[5],
     (unsigned)h->proto, (unsigned)data_len));
  SSH_DEBUG_HEXDUMP(
    SSH_D_PCKDMP, ("Data"), mblk->mBlkHdr.mData + sizeof *hdr, data_len);

  if (!h->cookie)
    {
      SSH_DEBUG(SSH_D_FAIL, ("MAC interface disappeared", strerror(errno)));
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }

  if (muxSend(h->cookie, mblk) != OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: muxSend: %s", strerror(errno)));
      netMblkClChainFree(mblk);
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }
  return SSH_NETCONFIG_ERROR_OK;
}

SshNetmacHandle
ssh_netmac_register(SshUInt32 ifnum,
                    SshUInt16 proto,
                    SshNetmacReceiveCallback receive_callback,
                    void *receive_context)
{
  SshNetmacHandle h = NULL;
  END_OBJ *end;
  char *name, *proto_name;
  int unit, n;

  if (!(end = (void *)ifnum))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown interface %d", (int)ifnum));
      return NULL;
    }
  name = end->devObject.name;
  unit = end->devObject.unit;

  /* create handle and associated data */
  if (!(h = ssh_calloc(1, sizeof *h)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory allocating MAC handle"));
      goto fail;
    }

  h->proto = proto;
  h->receive_callback = receive_callback;
  h->receive_context = receive_context;
  h->dev_fd = -1;

  /* create driver on first register */
  if (netmac_dev_cnt <= 0)
    {
      if (netmac_drv_num)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Driver number already nonzero"));
          goto fail;
        }
      n = iosDrvInstall(
        NULL, NULL, netmac_open, netmac_close,
        netmac_read, NULL, netmac_ioctl);
      if (n == ERROR)
        {
          SSH_DEBUG(
            SSH_D_FAIL, ("Failed: iosDrvInstall: %s", strerror(errno)));
          goto fail;
        }
      netmac_drv_num = n;
    }

  /* add device */
  ssh_snprintf(h->dev_name, sizeof h->dev_name, "/netmac/%s%d", name, unit);
  if (iosDevAdd((DEV_HDR *)h, h->dev_name, netmac_drv_num) != OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: iosDevAdd: %s", strerror(errno)));
      goto fail;
    }
  h->dev_added = 1;
  netmac_dev_cnt++;

  /* open a select()able file handle on the device */
  if ((h->dev_fd = open(h->dev_name, O_RDONLY | O_NONBLOCK, 0)) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: open: %s", strerror(errno)));
      goto fail;
    }

  /* register file handle in the event loop */
  if (!ssh_io_register_fd(h->dev_fd, netmac_io_callback, h))
    goto fail;
  h->dev_registered = 1;
  ssh_io_set_fd_request(h->dev_fd, SSH_IO_READ);

  /* get textual name for the protocol */
  switch (proto)
    {
    case 0x888e:
      proto_name = "EAPOL";
      break;
    default:
      proto_name = NULL;
      break;
    }

  /* bind protocol to the interface */
  h->cookie =
    muxBind(
      name,
      unit,
      netmac_receive,
      netmac_shutdown,
      netmac_restart,
      netmac_error,
      proto,
      proto_name,
      h);

  if (!h->cookie)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: muxBind: %s", strerror(errno)));
      goto fail;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Created MAC handle %p", h));
  return h;

 fail:
  if (h)
    ssh_netmac_unregister(h);
  return NULL;
}

SshNetconfigError
ssh_netmac_unregister(SshNetmacHandle h)
{
  if (h == NULL)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  /* unbind protocol from the interface */
  if (h->cookie)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Destroying MAC handle %p", h));

      if (muxUnbind(h->cookie, h->proto, netmac_receive) != OK)
        SSH_DEBUG(SSH_D_FAIL, ("Failed: muxUnbind: %s", strerror(errno)));
    }

  /* unregister file handle from the event loop */
  if (h->dev_registered)
    ssh_io_unregister_fd(h->dev_fd, FALSE);

  /* close file handle */
  if (h->dev_fd >= 0)
    close(h->dev_fd);

  /* remove device */
  if (h->dev_added)
    {
      iosDevDelete((DEV_HDR *)h);
      netmac_dev_cnt--;
    }

  /* delete driver on last unregister */
  if (netmac_dev_cnt <= 0)
    {
      if (!netmac_drv_num)
        SSH_DEBUG(SSH_D_FAIL, ("Driver number already zero"));
      else if (iosDrvRemove(netmac_drv_num, FALSE) != OK)
        SSH_DEBUG(SSH_D_FAIL, ("Failed: iosDrvRemove: %s", strerror(errno)));
      else
        netmac_drv_num = 0;
    }

  ssh_free(h);
  return SSH_NETCONFIG_ERROR_OK;
}

/*
 * Static functions.
 */

static
void netmac_io_callback(unsigned int events, void *context)
{
  SshNetmacHandle h = context;
  SshVxworksNetmacBufferStruct *b;
  struct enet_hdr *hdr;
  int n;
  char c;

  /* re-enable waiting for the device */
  ssh_io_set_fd_request(h->dev_fd, SSH_IO_READ);

  if (!(events & SSH_IO_READ))
    return;

  if ((n = read(h->dev_fd, &c, 1)) < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("%s: read: %s", h->dev_name, strerror(errno)));
      return;
    }
  else if (n == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("%s: short read", h->dev_name, strerror(errno)));
      return;
    }

  /* process all frames in the ring */
  while (1)
    {
      b = &h->rxring[h->rxring_out];

      if (!b->rdy)
        break;

      if (b->len < sizeof *hdr)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Short MAC frame received"));
          goto next;
        }
      hdr = (void *)b->buf;
      if (hdr->type != htons(h->proto))
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC frame with wrong length/type received"));
          goto next;
        }
      SSH_DEBUG(
        SSH_D_LOWOK,
        ("MAC frame received, "
         "dst %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
         "src %02.2X:%02.2X:%02.2X:%02.2X:%02.2X:%02.2X, "
         "length/type 0x%04.4X, data length %u",
         (unsigned)hdr->dst[0], (unsigned)hdr->dst[1], (unsigned)hdr->dst[2],
         (unsigned)hdr->dst[3], (unsigned)hdr->dst[4], (unsigned)hdr->dst[5],
         (unsigned)hdr->src[0], (unsigned)hdr->src[1], (unsigned)hdr->src[2],
         (unsigned)hdr->src[3], (unsigned)hdr->src[4], (unsigned)hdr->src[5],
         (unsigned)h->proto, (unsigned)(b->len - sizeof *hdr)));
      SSH_DEBUG_HEXDUMP(
        SSH_D_PCKDMP, ("Data"), b->buf + sizeof *hdr, b->len - sizeof *hdr);
      if (h->receive_callback)
        (*h->receive_callback)(
          hdr->dst, hdr->src, b->buf + sizeof *hdr, b->len - sizeof *hdr,
          h->receive_context);

    next:
      b->rdy = 0;
      h->rxring_out++;
      h->rxring_out %= sizeof h->rxring / sizeof h->rxring[0];
    }

  return;
}

static int
netmac_open(SshNetmacHandle h, char *name, int mode)
{
  if (h->dev_open)
    return ERROR;
  h->dev_open = 1;

  selWakeupListInit(&h->dev_swl);
  return (int)h;
}

static int
netmac_close(SshNetmacHandle h)
{
  if (!h->dev_open)
    return ERROR;
  h->dev_open = 0;

#if !defined(_WRS_VXWORKS_5_X) && !defined(_WRS_VXWORKS_MAJOR)
  if (semDestroy(&h->dev_swl.listMutex, FALSE) != OK)
    return ERROR;
#else
  selWakeupListTerm(&h->dev_swl);
#endif
  return OK;
}

static int
netmac_read(SshNetmacHandle h, char *buf, size_t len)
{
  if (!h->dev_readable)
    return 0;

  h->dev_readable = 0;
  return 1;
}

static int
netmac_ioctl(SshNetmacHandle h, int cmd, int arg)
{
  SEL_WAKEUP_NODE *node = (void *)arg;

  switch (cmd)
    {
    case FIOSELECT:
      selNodeAdd(&h->dev_swl, node);
      if (selWakeupType(node) == SELREAD && h->dev_readable)
        selWakeup(node);
      return OK;

    case FIOUNSELECT:
      selNodeDelete(&h->dev_swl, node);
      return OK;

    default:
      return ERROR;
    }
}

static BOOL
netmac_receive(
  void *cookie, long type,M_BLK_ID mblk, LL_HDR_INFO *ll, void *spare)
{
  SshNetmacHandle h;
  SshVxworksNetmacBufferStruct *b;

  if (!spare)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Null spare pointer"));
      return ERROR;
    }
  h = spare;

  if (cookie != h->cookie)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid cookie"));
      return ERROR;
    }

  b = &h->rxring[h->rxring_in];

  if (b->rdy)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No MAC buffers"));
      goto end;
    }

  if (!(mblk->mBlkHdr.mFlags & M_PKTHDR))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid mBlk header"));
      goto end;
    }

  if (mblk->mBlkPktHdr.len > sizeof b->buf)
    {
      SSH_DEBUG(SSH_D_FAIL, ("MAC frame too large"));
      goto end;
    }

  netMblkToBufCopy(mblk, b->buf, NULL);
  b->len = mblk->mBlkPktHdr.len;

  b->rdy = 1;
  h->rxring_in++;
  h->rxring_in %= sizeof h->rxring / sizeof h->rxring[0];

  h->dev_readable = 1;
  selWakeupAll(&h->dev_swl, SELREAD);

 end:
  netMblkClChainFree(mblk);
  return TRUE;
}

static STATUS
netmac_shutdown(void *cookie, void *spare)
{
  SshNetmacHandle h;

  if (!spare)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Null spare pointer"));
      return ERROR;
    }
  h = spare;

  if (cookie != h->cookie)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid cookie"));
      return ERROR;
    }

  if (muxUnbind(h->cookie, h->proto, netmac_receive) != OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed: muxUnbind: %s", strerror(errno)));
      return ERROR;
    }

  h->cookie = NULL;
  return OK;
}

static STATUS
netmac_restart(void *cookie, void *spare)
{
  SshNetmacHandle h;

  if (!spare)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Null spare pointer"));
      return ERROR;
    }
  h = spare;

  if (cookie != h->cookie)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid cookie"));
      return ERROR;
    }

  return OK;
}

static void
netmac_error(END_OBJ *end, END_ERR *err, void *spare)
{
  const char *name;
  int unit;

  if (!end)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Null END pointer"));
      return;
    }
  name = end->devObject.name;
  unit = end->devObject.unit;

  SSH_DEBUG(
    SSH_D_MIDOK, ("END event %d on %s%d", (int)err->errCode, name, unit));
}

#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */
